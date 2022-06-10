#ifndef FOC_PROJECT_SRC_S3L_CLIENTHELLOMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_CLIENTHELLOMESSAGE_H_
#include "S3LMessage.h"

struct ClientHelloMessage : public S3LMessage {
  S3LHeader rh{};
  std::array<u8, kIvLength> iv{};
  u64 client_id{};
  u32 client_dh_pubkey_length{};
  u32 sign_length{};

  Vec<u8> client_dh_pubkey{};
  Vec<u8> sign{};

  [[nodiscard]] size_t GetTotalSize() const;

  [[nodiscard]] NetworkBuffer Serialize() const override;

  ClientHelloMessage() : rh{kClientHello} {}

  explicit ClientHelloMessage(const S3LHeader& rh) : rh{rh} {}

  static std::shared_ptr<ClientHelloMessage> Deserialize(
      const S3LHeader& rh, const Vec<u8>& content_bytes);

  [[nodiscard]] Vec<u8> GetDataToSign() const;

  static ClientHelloMessage Create(crypto::DH_mng& dh_context, u64 id,
                                   const SecVec<u8>& prv_key);
};

#endif  // FOC_PROJECT_SRC_S3L_CLIENTHELLOMESSAGE_H_
