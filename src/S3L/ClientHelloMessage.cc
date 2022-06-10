#include "ClientHelloMessage.h"

size_t ClientHelloMessage::GetTotalSize() const {
  return SizeCalculator{} << iv << client_id << client_dh_pubkey_length
                          << sign_length << client_dh_pubkey << sign;
}

NetworkBuffer ClientHelloMessage::Serialize() const {
  return NetworkBuffer{} << rh << iv << client_id << client_dh_pubkey_length
                         << sign_length << client_dh_pubkey << sign;
}

std::shared_ptr<ClientHelloMessage> ClientHelloMessage::Deserialize(
    const S3LHeader& rh, const Vec<u8>& content_bytes) {
  auto network_buffer = NetworkBuffer{content_bytes};
  auto rv = std::make_shared<ClientHelloMessage>(rh);
  network_buffer >> rv->iv >> rv->client_id >> rv->client_dh_pubkey_length >>
      rv->sign_length;
  rv->client_dh_pubkey = network_buffer.PopBytes(rv->client_dh_pubkey_length);
  rv->sign = network_buffer.PopBytes(rv->sign_length);
  return rv;
}

Vec<u8> ClientHelloMessage::GetDataToSign() const {
  auto tmp1 = NetworkBuffer{};
  tmp1 << iv << client_id << client_dh_pubkey_length << client_dh_pubkey;
  return tmp1.Data<Vec<u8>>();
}

ClientHelloMessage ClientHelloMessage::Create(crypto::DH_mng& dh_context,
                                              u64 id,
                                              const SecVec<u8>& prv_key) {
  auto rv = ClientHelloMessage{};
  rv.iv = crypto::GenerateRandomBytes<kIvLength>();
  rv.client_id = id;
  rv.client_dh_pubkey = dh_context.GetPubkeyAsBytes();
  rv.client_dh_pubkey_length = rv.client_dh_pubkey.size();
  rv.sign = crypto::Signature::Make(prv_key, rv.GetDataToSign());
  rv.sign_length = rv.sign.size();
  rv.rh.length = rv.GetTotalSize();
  return rv;
}
