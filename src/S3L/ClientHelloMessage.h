#ifndef FOC_PROJECT_SRC_S3L_CLIENTHELLOMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_CLIENTHELLOMESSAGE_H_
#include "S3LMessage.h"

struct ClientHelloMessage : public S3LMessage {
  S3LHeader header{};
  u32 client_dh_pubkey_length{};
  Vec<u8> client_dh_pubkey{};

  [[nodiscard]] size_t GetTotalSize() const;

  [[nodiscard]] NetworkBuffer Serialize() const override;

  ClientHelloMessage() : header{kClientHello} {}

  explicit ClientHelloMessage(const S3LHeader &h) : header{h} {}

  static std::shared_ptr<ClientHelloMessage> Deserialize(
      const S3LHeader &h, const Vec<u8> &content_bytes);

  [[nodiscard]] Vec<u8> GetDataToSign() const;

  static ClientHelloMessage Create(crypto::DiffieHellmanManager &dh_context);
};

#endif  // FOC_PROJECT_SRC_S3L_CLIENTHELLOMESSAGE_H_
