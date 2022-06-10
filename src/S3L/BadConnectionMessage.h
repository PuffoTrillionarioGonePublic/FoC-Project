#ifndef FOC_PROJECT_SRC_S3L_BADCONNECTIONMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_BADCONNECTIONMESSAGE_H_

#include "S3LMessage.h"

struct BadConnectionMessage : public S3LMessage {
  S3LHeader rh{};

  BadConnectionMessage() : rh{kBadConnection} {}

  explicit BadConnectionMessage(const S3LHeader &rh) : rh{rh} {}

  [[nodiscard]]
  NetworkBuffer Serialize() const override;

  static std::shared_ptr<BadConnectionMessage>
  Deserialize(const S3LHeader &rh, const Vec<u8> &content_bytes);
};


#endif //FOC_PROJECT_SRC_S3L_BADCONNECTIONMESSAGE_H_
