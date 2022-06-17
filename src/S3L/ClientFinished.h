#ifndef FOC_PROJECT_SRC_S3L_CLIENTFINISHED_H_
#define FOC_PROJECT_SRC_S3L_CLIENTFINISHED_H_
#include "constants.h"
#include <array>
#include "../util.h"
#include "S3LHeader.h"
#include "S3LMessage.h"
#include <memory>

struct ClientFinished : public S3LMessage {
  S3LHeader header;
  u64 client_id;
  std::array<u8, kIvLength> iv;
  u32 signature_length;
  Vec<u8> signature;
  std::array<u8, kMacLength> mac;

  NetworkBuffer Serialize() const override {
    return NetworkBuffer{} << header << client_id << iv << signature_length << signature << mac;
  }

  size_t GetTotalSize() const {
    return SizeCalculator{} << client_id << iv << signature_length << signature << mac;
  }

  ClientFinished() : header{kClientFinished} {}

  explicit ClientFinished(const S3LHeader &h, const Vec<u8> &content_bytes) : header{h} {
    auto nb = NetworkBuffer{} << content_bytes;
    nb >> client_id >> iv >> signature_length;
    signature = nb.PopBytes(signature_length);
    nb >> mac;
  }

  Vec<u8> GetDataToMac() {
    return NetworkBuffer{} << client_id << iv;
  }

  static std::shared_ptr<ClientFinished> Deserialize(const S3LHeader &h,
                                                     const Vec<u8> &content_bytes) {
    return std::make_shared<ClientFinished>(h, content_bytes);
  }



  void ValidateOrThrow(const SecArray<u8, kAuthKeyLength> &auth_key,
                       const Vec<u8> &client_dh_pub_key,
                       const Vec<u8> &server_dh_pub_key) const {
    Vec<u8> client_pub_key = GetPublicKeyFromId(client_id);
    Vec<u8> data_to_sign = NetworkBuffer{} << client_dh_pub_key << server_dh_pub_key;
    if (!crypto::SignatureVerification::Make(client_pub_key, data_to_sign, signature)) {
      throw std::runtime_error{"invalid signature"};
    }
    Vec<u8> data_to_mac = NetworkBuffer{} << client_id << iv << signature;
    auto actual_mac = crypto::Mac(data_to_mac, auth_key);
    if (!AreSecureEqual(actual_mac, mac)) {
      throw std::runtime_error{"invalid mac"};
    }
  }

  static ClientFinished CreateAndAuthenticate(const SecArray<u8, kAuthKeyLength> &auth_key,
                                              u64 client_id,
                                              const Vec<u8> &client_dh_pub_key,
                                              const Vec<u8> &server_dh_pub_key,
                                              const SecVec<u8> &prv_key) {
    auto self = ClientFinished{};
    self.client_id = client_id;
    self.iv = crypto::GenerateRandomBytes<kIvLength>();
    Vec<u8> data_to_sign = NetworkBuffer{} << client_dh_pub_key << server_dh_pub_key;
    self.signature = crypto::Signature::Make(prv_key, data_to_sign);
    self.signature_length = self.signature.size();
    Vec<u8> data_to_mac = NetworkBuffer{} << self.client_id << self.iv << self.signature;
    self.mac = crypto::Mac(data_to_mac, auth_key);
    self.header.length = self.GetTotalSize();
    return self;
  }

};

#endif //FOC_PROJECT_SRC_S3L_CLIENTFINISHED_H_
