#include "ClientHelloMessage.h"

size_t ClientHelloMessage::GetTotalSize() const {
  return SizeCalculator{} << client_dh_pubkey_length << client_dh_pubkey;
}

NetworkBuffer ClientHelloMessage::Serialize() const {
  return NetworkBuffer{} << header << client_dh_pubkey_length << client_dh_pubkey;
}

std::shared_ptr<ClientHelloMessage> ClientHelloMessage::Deserialize(
    const S3LHeader &h, const Vec<u8> &content_bytes) {
  auto network_buffer = NetworkBuffer{content_bytes};
  auto rv = std::make_shared<ClientHelloMessage>(h);
  network_buffer >> rv->client_dh_pubkey_length;
  rv->client_dh_pubkey = network_buffer.PopBytes(rv->client_dh_pubkey_length);
  return rv;
}

Vec<u8> ClientHelloMessage::GetDataToSign() const {
  auto tmp1 = NetworkBuffer{};
  tmp1 << client_dh_pubkey_length << client_dh_pubkey;
  return tmp1.Data<Vec<u8>>();
}

ClientHelloMessage ClientHelloMessage::Create(crypto::DiffieHellmanManager &dh_context) {
  auto rv = ClientHelloMessage{};
  rv.client_dh_pubkey = dh_context.GetPubkeyAsBytes();
  rv.client_dh_pubkey_length = rv.client_dh_pubkey.size();
  rv.header.length = rv.GetTotalSize();
  return rv;
}
