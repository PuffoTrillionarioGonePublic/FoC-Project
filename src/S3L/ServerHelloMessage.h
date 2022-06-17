#ifndef FOC_PROJECT_SRC_S3L_SERVERHELLOMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_SERVERHELLOMESSAGE_H_
#include "ClientHelloMessage.h"
#include "S3LMessage.h"

struct ServerHelloMessage : public S3LMessage {
  S3LHeader header{};
  u32 signature_length{};
  u32 server_dh_pubkey_length{};
  u32 certificate_length{};

  Vec<u8> signature{};
  Vec<u8> server_dh_pubkey{};
  Vec<u8> certificate{};

  [[nodiscard]] size_t GetTotalSize() const;

  [[nodiscard]] NetworkBuffer Serialize() const override;

  ServerHelloMessage(const S3LHeader &h, const Vec<u8> &content_bytes);

  ServerHelloMessage() : header{kServerHello} {}

  //explicit ServerHelloMessage(const S3LHeader &rh) : header{rh} {}

  [[nodiscard]] Vec<u8> GetDataToSignWith(
      const Vec<u8> &client_dh_pub_key) const;

  static ServerHelloMessage From(
      const Vec<u8> &server_dh_public_key,
      const Vec<u8> &client_dh_pubkey,
      const Vec<u8> &certificate, const SecVec<u8> &prv_key);

  static std::shared_ptr<ServerHelloMessage> Deserialize(
      const S3LHeader &rh, const Vec<u8> &content_bytes);

  void ValidateOrThrow(const Vec<u8> &client_dh_pubkey,
                       const std::string &common_name,
                       const std::string &root_ca_path) const;
};

#endif  // FOC_PROJECT_SRC_S3L_SERVERHELLOMESSAGE_H_
