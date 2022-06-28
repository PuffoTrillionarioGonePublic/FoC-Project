#include "SecureDataChannel.h"
#include "DataMessage.h"
#include "ClientFinished.h"
#include "utility.h"
#include <iostream>
#include <memory>

auto SecureDataChannel::MakeClientSideHandshake(IOChannel &channel,
                                                const SecVec<u8> &prv_key,
                                                u64 id,
                                                const std::string &common_name,
                                                const std::string &root_ca_path)
-> std::tuple<SecArray<u8, kAuthKeyLength>,
              SecArray<u8, kSymmetricKeyLength>,
              std::array<u8, kIvLength>,
              Vec<u8> > {
  auto dh_context = crypto::DiffieHellmanManager{};
  auto client_hello = ClientHelloMessage::Create(dh_context);
  // std::clog << "c) Client Public Key spedita: " << client_hello.client_dh_pubkey << std::endl;
  WriteS3LMessage(channel, client_hello);
  auto server_hello = ReadS3LMessage<ServerHelloMessage>(channel);
  server_hello.ValidateOrThrow(client_hello.client_dh_pubkey, common_name, root_ca_path);
  // std::clog << "c) Server Public Key ricevuta: " << server_hello.server_dh_pubkey << std::endl;
  SecArray<u8, kSha256Length> key = dh_context.GetSharedKey(server_hello.server_dh_pubkey);
  auto [auth_key, enc_key] = SplitArray<kAuthKeyLength, kSymmetricKeyLength>(key);
  auto client_finished = ClientFinished::CreateAndAuthenticate(auth_key,
                                                               id,
                                                               client_hello.client_dh_pubkey,
                                                               server_hello.server_dh_pubkey,
                                                               prv_key);
  WriteS3LMessage(channel, client_finished);

  return {auth_key, enc_key, client_finished.iv,
      crypto::ExtractPublicKey(server_hello.certificate)};
}

auto SecureDataChannel::MakeServerSideHandshake(IOChannel &channel,
                                                const SecVec<u8> &prv_key,
                                                const Vec<u8> &certificate)
-> std::tuple<SecArray<u8, kAuthKeyLength>,
              SecArray<u8, kSymmetricKeyLength>,
              std::array<u8, kIvLength>,
              u64> {
  auto client_hello = ReadS3LMessage<ClientHelloMessage>(channel);

  auto dh_context = crypto::DiffieHellmanManager();
  // std::clog << "s) Client Pub Key ricevuta: " << client_hello.client_dh_pubkey << std::endl;
  SecArray<u8, kSha256Length> key = dh_context.GetSharedKey(client_hello.client_dh_pubkey);
  Vec<u8> dh_pub_key = dh_context.GetPubkeyAsBytes();
  auto server_hello = ServerHelloMessage::From(dh_pub_key, client_hello.client_dh_pubkey, certificate, prv_key);
  // std::clog << "s) Server Public Key spedita: " << server_hello.server_dh_pubkey << std::endl;
  WriteS3LMessage(channel, server_hello);
  auto [auth_key, enc_key] = SplitArray<kAuthKeyLength, kSymmetricKeyLength>(key);
  auto client_finished = ReadS3LMessage<ClientFinished>(channel);
  client_finished.ValidateOrThrow(auth_key,
                                  client_hello.client_dh_pubkey,
                                  server_hello.server_dh_pubkey);
  return {auth_key, enc_key, client_finished.iv, client_finished.client_id};
}

void SecureDataChannel::ValidateOrThrow() {
  if (IsClosed_())
    throw std::runtime_error{"SecureDataChannel is closed"};
  if (!ready_) {
    auto [auth_key, symmetric_key, iv, peer_public_key] = init_cb_(*io_);
    // std::clog << "Auth key: " << auth_key << std::endl;
    // std::clog << "symmetric key: " << symmetric_key << std::endl;
    auth_key_ = auth_key;
    symmetric_key_ = symmetric_key;
    peer_public_key_ = peer_public_key;
    iv_ = iv;
    encryptor_ = crypto::AES128CTREncryptor{symmetric_key_, iv_};
    decryptor_ = crypto::AES128CTRDecryptor{symmetric_key_, iv_};
    ready_ = true;
  }
}

void SecureDataChannel::Close_() noexcept {
  if (IsClosed_()) {
    return;
  }

  if (ready_) {
	try {
		WriteS3LMessage(*io_, ShutdownMessage::Create(), encryptor_, auth_key_);
		auto shutdown_message =
			ReadS3LMessage<ShutdownMessage>(*io_, decryptor_, auth_key_);

	} catch (std::exception &err) {
		// std::clog << err.what() << std::endl;
	}
  }
  ready_ = false;

  io_->Close();
  closed_ = true;
}

SecureDataChannel::SecureDataChannel(
    std::shared_ptr<IOChannel> io, const SecArray<u8, kAuthKeyLength> &auth_key,
    const SecArray<u8, kSymmetricKeyLength> &enc_key,
    const std::array<u8, kIvLength> &iv, const Vec<u8> &peer_public_key) {
  closed_ = false;
  io_ = std::move(io);
  auth_key_ = auth_key;
  symmetric_key_ = enc_key;
  iv_ = iv;
  encryptor_ = crypto::AES128CTREncryptor{symmetric_key_, iv_};
  decryptor_ = crypto::AES128CTRDecryptor{symmetric_key_, iv_};
  peer_public_key_ = peer_public_key;
  ready_ = true;
}
SecureDataChannel::SecureDataChannel(std::shared_ptr<IOChannel> io,
                                     InitCallback init) {
  closed_ = false;
  ready_ = false;
  init_cb_ = std::move(init);
  if (io == nullptr) {
    throw std::invalid_argument{"io channel can't be null"};
  }
  io_ = std::move(io);
}

void SecureDataChannel::Write(const Vec<u8> &v) {
  ValidateOrThrow();
  for (size_t i = 0; i < v.size(); i += kMaxDataMessagePayloadSize) {
    auto begin = v.begin() + i;
    auto end = v.begin() + std::min(v.size(), i + kMaxDataMessagePayloadSize);
    auto buf = Vec<u8>(begin, end);
    auto data = DataMessage::Create(buf, sent_sequence_number_++);
    WriteS3LMessage(*io_, data, encryptor_, auth_key_);
  }
}

Vec<u8> SecureDataChannel::Read(size_t n) {
  // (* controlli sul canale e sull'input
  ValidateOrThrow();
  using difference_type_t = decltype(rdbuf_)::difference_type;
  // this should be true for every platform
  static_assert(sizeof(size_t) >= sizeof(difference_type_t));
  auto num_bytes = numeric_cast<difference_type_t>(n);
  {
    auto buffer_size = numeric_cast<difference_type_t>(rdbuf_.size());
    if (buffer_size >
        std::numeric_limits<difference_type_t>::max() - num_bytes) {
      throw std::invalid_argument{"buffer pieno"};
    }
  }

  // *)

  // finche` non ho ricevuto byte sufficienti a soddisfare la richiesta
  // leggo message dall'io
  while (numeric_cast<difference_type_t>(rdbuf_.size()) < num_bytes) {
    auto msg = ReadS3LMessage(*io_, decryptor_, auth_key_);
    if (InstanceOf<DataMessage>(msg)) {
      auto data_message = std::dynamic_pointer_cast<DataMessage>(msg);
      if (!data_message->VerifyContent(received_sequence_number_++)) {
        throw std::runtime_error{"content not valid"};
      }

      rdbuf_.insert(rdbuf_.end(), data_message->bytes.begin(),
                    data_message->bytes.end());

    } else if (InstanceOf<ShutdownMessage>(msg)) {
      Close_();
      throw std::runtime_error{"io correctly closed"};
    } else {
      Close_();
      throw std::runtime_error{"io abnormal close for invalid packet received"};
    }
  }
  /// trasferisco i byte dal buffer di lettura
  /// al vettore da restituire
  auto rv = Vec<u8>(rdbuf_.begin(), rdbuf_.begin() + num_bytes);
  rdbuf_.erase(rdbuf_.begin(), rdbuf_.begin() + num_bytes);
  return rv;
}

std::shared_ptr<IOChannel> SecureDataChannel::ConnectToDataChannelAsClient(
    std::shared_ptr<IOChannel> io, const SecVec<u8> &prv_key, u64 id,
    const std::string &common_name, const std::string &root_ca_path) {
  auto make_client_side_handshake = [prv_key, id, common_name,
      root_ca_path](IOChannel &io) {
    return MakeClientSideHandshake(io, prv_key, id, common_name, root_ca_path);
  };
  auto channel = std::make_shared<SecureDataChannel>(
      std::move(io), make_client_side_handshake);
  return channel;
}
auto SecureDataChannel::ConnectToDataChannelAsServer(
    std::shared_ptr<IOChannel> io, const SecVec<u8> &prv_key,
    const Vec<u8> &certificate) -> std::tuple<std::shared_ptr<IOChannel>, u64> {
  auto [auth_key, enc_key, iv, client_id] =
      MakeServerSideHandshake(*io, prv_key, certificate);
  auto channel = std::make_shared<SecureDataChannel>(
      std::move(io), auth_key, enc_key, iv, GetPublicKeyFromId(client_id));
  return {channel, client_id};
}
