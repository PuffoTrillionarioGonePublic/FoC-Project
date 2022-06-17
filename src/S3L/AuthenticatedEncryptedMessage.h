#ifndef FOC_PROJECT_SRC_S3L_AUTHENTICATEDENCRYPTEDMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_AUTHENTICATEDENCRYPTEDMESSAGE_H_

#include "constants.h"
#include "S3LMessage.h"
#include "../util.h"

class AuthenticatedEncryptedMessage : public S3LMessage {
  virtual std::array<u8, kMacLength> &GetMac() = 0;
  virtual void SetMac(const std::array<u8, kMacLength> &) = 0;
};
#endif  // FOC_PROJECT_SRC_S3L_AUTHENTICATEDENCRYPTEDMESSAGE_H_
