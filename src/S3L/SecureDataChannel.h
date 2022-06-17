#ifndef S3L_SECUREDATACHANNEL_H
#define S3L_SECUREDATACHANNEL_H

#include "AuthenticatedEncryptedMessage.h"
#include "BadConnectionMessage.h"
#include "ClientHelloMessage.h"
#include "DataMessage.h"
#include "IOChannel.h"
#include "NetworkBuffer.h"
#include "S3LHeader.h"
#include "constants.h"
#include "S3LMessage.h"
#include "ServerHelloMessage.h"
#include "ShutdownMessage.h"
#include "ClientFinished.h"
#include <algorithm>
#include <deque>
#include <memory>
#include <utility>

inline std::shared_ptr<S3LMessage> DeserializeMessage(
    const S3LHeader &ri, const Vec<u8> &content_bytes) {
  switch (ri.content_type) {
    case kClientHello: {
      return ClientHelloMessage::Deserialize(ri, content_bytes);
    }
    case kServerHello: {
      return ServerHelloMessage::Deserialize(ri, content_bytes);
    }
    case kClientFinished: {
      return ClientFinished::Deserialize(ri, content_bytes);
    }
    case kShutdown: {
      return ShutdownMessage::Deserialize(ri, content_bytes);
    }
    case kData: {
      return DataMessage::Deserialize(ri, content_bytes);
    }
    case kBadConnection: {
      return BadConnectionMessage::Deserialize(ri, content_bytes);
    }

    default:
      throw std::runtime_error{"invalid ContentTrait type"};
  }
  // non raggiungibile
}

inline auto ReadS3LMessage(IOChannel &channel) -> std::shared_ptr<S3LMessage> {
  auto bytes = channel.Read(S3LHeader::kBytesLength);
  auto info_buf = NetworkBuffer{bytes};
  auto rh = S3LHeader{};
  info_buf >> rh;
  auto content_bytes = channel.Read(rh.length);
  auto rv = DeserializeMessage(rh, content_bytes);
  return rv;
}

template <typename T>
inline T ReadS3LMessage(IOChannel &channel) {
  std::shared_ptr<T> ptr =
      std::dynamic_pointer_cast<T>(ReadS3LMessage(channel));
  if (!ptr) {
    throw std::runtime_error{"Can't cast message"};
  }
  return *ptr;
}

inline auto ReadS3LMessage(IOChannel &channel,
                        crypto::AES128CTRDecryptor &decryptor,
                        const SecArray<u8, kAuthKeyLength> &auth_key)
    -> std::shared_ptr<S3LMessage> {
  auto header_bytes = channel.Read(S3LHeader::kBytesLength);
  auto rh = S3LHeader{};
  NetworkBuffer{} << header_bytes >> rh;
  auto bytes = channel.Read(rh.length - kMacLength);
  auto mac_bytes = channel.Read(kMacLength);
  std::array<u8, kMacLength> mac{};
  std::copy(mac_bytes.begin(), mac_bytes.end(), mac.begin());
  Vec<u8> bytes_to_mac = NetworkBuffer{} << rh << bytes;

  auto candidate_mac = crypto::Mac(bytes_to_mac, auth_key);
  if (!AreSecureEqual(mac,  candidate_mac)) {
    throw std::runtime_error{"Invalid mac"};
  }
  bytes = decryptor.Decrypt(bytes);
  bytes.insert(bytes.end(), mac.begin(), mac.end());
  return DeserializeMessage(rh, bytes);
}

template <typename T>
inline T ReadS3LMessage(IOChannel &channel,
                        crypto::AES128CTRDecryptor &decryptor,
                        const SecArray<u8, kAuthKeyLength> &auth_key) {
  std::shared_ptr<T> ptr = std::dynamic_pointer_cast<T>(
      ReadS3LMessage(channel, decryptor, auth_key));
  if (!ptr) {
    throw std::runtime_error{"Can't cast message"};
  }
  return *ptr;
}

inline void WriteS3LMessage(IOChannel &channel, const S3LMessage &message,
                            crypto::AES128CTREncryptor &encryptor,
                            const SecArray<u8, kAuthKeyLength> &auth_key) {
  auto data = (Vec<u8>) message.Serialize();
//  auto v = SecVec<u8>(enc_key.begin(), enc_key.end());
  Vec<u8> content;
  if (InstanceOf<AuthenticatedEncryptedMessage>(message)) {
    content = Vec<u8>(data.begin() + S3LHeader::kBytesLength,
                      data.end() - kMacLength);
  } else {
    content = Vec<u8>(data.begin() + S3LHeader::kBytesLength, data.end());
  }

  auto tmp = encryptor.Encrypt(content);

  if (InstanceOf<AuthenticatedEncryptedMessage>(message)) {
    auto rh = Vec<u8>(data.begin(), data.begin() + S3LHeader::kBytesLength);
    Vec<u8> bytes_to_mac = NetworkBuffer{} << rh << tmp;
    std::array<u8, kMacLength> mac = crypto::Mac(bytes_to_mac, auth_key);
    tmp.insert(tmp.end(), mac.begin(), mac.end());
  }
  for (size_t i = S3LHeader::kBytesLength; i < data.size(); ++i) {
    data[i] = tmp[i - S3LHeader::kBytesLength];
  }
  channel.Write(data);
}

/// funzione bloccante, si blocca finche` non scrive un message intero
inline void WriteS3LMessage(IOChannel &channel, const S3LMessage &message) {
  channel.Write(message.Serialize());
}

/// canale col quale si leggono e scrivono DataMessage, dall'interfaccia
/// e` possibile solo scrivere e leggere byte e controllare lo stato
/// del canale
class SecureDataChannel : public IOChannel {
  static constexpr size_t kMaxDataMessagePayloadSize = 4096;

  using InitCallback = std::function<std::tuple<
      SecArray<u8, kAuthKeyLength>, SecArray<u8, kSymmetricKeyLength>,
      std::array<u8, kIvLength>, Vec<u8> >(IOChannel &)>;

  InitCallback init_cb_;

  std::shared_ptr<IOChannel> io_;
  /// buffer da cui si legge
  std::deque<u8> rdbuf_;
  bool ready_;
  bool closed_;
  SecArray<u8, kAuthKeyLength> auth_key_{};
  SecArray<u8, kSymmetricKeyLength> symmetric_key_{};
  crypto::AES128CTREncryptor encryptor_;
  crypto::AES128CTRDecryptor decryptor_;

  std::array<u8, kSymmetricKeyLength> iv_{};
  Vec<u8> peer_public_key_;
  u32 sent_sequence_number_{};
  u32 received_sequence_number_{};
  /// questa funzione verifica che il canale sia inizializzato
  /// e che sia possibile utilizzarlo, altrimenti lancia un'eccezione
  void ValidateOrThrow();
  void Close_() noexcept;

  [[nodiscard]] bool IsClosed_() const { return closed_ || io_->IsClosed(); }

  static auto MakeClientSideHandshake(IOChannel &channel,
                                      const SecVec<u8> &prv_key, u64 id,
                                      const std::string &common_name,
                                      const std::string &root_ca_path)
      -> std::tuple<SecArray<u8, kAuthKeyLength>,
                    SecArray<u8, kSymmetricKeyLength>,
                    std::array<u8, kIvLength>, Vec<u8> >;

  static auto MakeServerSideHandshake(IOChannel &channel,
                                      const SecVec<u8> &prv_key,
                                      const Vec<u8> &certificate)
      -> std::tuple<SecArray<u8, kAuthKeyLength>,
                    SecArray<u8, kSymmetricKeyLength>,
                    std::array<u8, kIvLength>, u64>;

 public:

  SecureDataChannel(std::shared_ptr<IOChannel> io,
                    const SecArray<u8, kAuthKeyLength> &auth_key,
                    const SecArray<u8, kSymmetricKeyLength> &enc_key,
                    const std::array<u8, kIvLength> &iv,
                    const Vec<u8> &peer_public_key);

  SecureDataChannel(std::shared_ptr<IOChannel> io, InitCallback init);

  void Write(const Vec<u8> &v) override;

  Vec<u8> Read(size_t n) override;

  bool IsClosed() override { return IsClosed_(); }

  void Close() noexcept override { Close_(); }

  static std::shared_ptr<IOChannel> ConnectToDataChannelAsClient(
      std::shared_ptr<IOChannel> io, const SecVec<u8> &prv_key, u64 id,
      const std::string &common_name, const std::string &root_ca_path);

  static auto ConnectToDataChannelAsServer(std::shared_ptr<IOChannel> io,
                                           const SecVec<u8> &prv_key,
                                           const Vec<u8> &certificate)
      -> std::tuple<std::shared_ptr<IOChannel>, u64>;

  ~SecureDataChannel() override { Close_(); }
};

#endif  // S3L_SECUREDATACHANNEL_H
