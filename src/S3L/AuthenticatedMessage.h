#ifndef FOC_PROJECT_SRC_S3L_AUTHENTICATEDMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_AUTHENTICATEDMESSAGE_H_

#include "S3L/constants.h"
#include "S3LMessage.h"
#include "util.h"

class AuthenticatedMessage : public S3LMessage {
  virtual std::array<u8, kMacLength>& GetMac() = 0;
  virtual void SetMac(const std::array<u8, kMacLength>&) = 0;
};
#endif  // FOC_PROJECT_SRC_S3L_AUTHENTICATEDMESSAGE_H_
