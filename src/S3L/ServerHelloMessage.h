#ifndef FOC_PROJECT_SRC_S3L_SERVERHELLOMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_SERVERHELLOMESSAGE_H_
#include "ClientHelloMessage.h"
#include "S3LMessage.h"

struct ServerHelloMessage : public S3LMessage {
  S3LHeader rh{};
  u32 sign_length{};
  u32 server_length{};
  u32 certificate_length{};
  Vec<u8> sign_server_client_random{};
  Vec<u8> server_dh_pubkey{};
  Vec<u8> certificate{};

  [[nodiscard]] size_t GetTotalSize() const;

  [[nodiscard]] NetworkBuffer Serialize() const override;

  ServerHelloMessage()
      : rh{kServerHello, sizeof(server_length) + sizeof(certificate_length)} {}

  explicit ServerHelloMessage(const S3LHeader& rh) : rh{rh} {}

  [[nodiscard]] Vec<u8> GetDataToSignWith(
      const Vec<u8>& client_dh_pub_key) const;

  static ServerHelloMessage From(
      const Vec<u8>& dh_public_key,
      const ClientHelloMessage& received_client_hello,
      const Vec<u8>& certificate, const SecVec<u8>& prv_key);

  static std::shared_ptr<ServerHelloMessage> Deserialize(
      const S3LHeader& rh, const Vec<u8>& content_bytes);

  void ValidateOrThrow(const Vec<u8>& client_dh_pubkey,
                       const std::string& common_name,
                       const std::string& root_ca_path) const;
};

#endif  // FOC_PROJECT_SRC_S3L_SERVERHELLOMESSAGE_H_
