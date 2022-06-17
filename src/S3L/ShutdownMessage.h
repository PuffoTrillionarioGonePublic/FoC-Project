#ifndef FOC_PROJECT_SRC_S3L_SHUTDOWNMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_SHUTDOWNMESSAGE_H_

#include "AuthenticatedEncryptedMessage.h"
#include "NetworkBuffer.h"
#include "constants.h"
#include <iostream>

struct ShutdownMessage : public AuthenticatedEncryptedMessage {
  S3LHeader rh{};
  std::array<u8, kMacLength> mac{};

  ShutdownMessage() : rh{kShutdown, sizeof(mac)} {}

  explicit ShutdownMessage(const S3LHeader &rh) : rh{rh} {}

  [[nodiscard]] NetworkBuffer Serialize() const override;

  static ShutdownMessage Create();

  Vec<u8> GetDataToMac() const { return NetworkBuffer{} << rh; }

  std::array<u8, kMacLength> &GetMac() override { return mac; }

  void SetMac(const std::array<u8, kMacLength> &m) override { mac = m; }

  static std::shared_ptr<ShutdownMessage> Deserialize(
      const S3LHeader &rh, const Vec<u8> &content_bytes);
};

#endif  // FOC_PROJECT_SRC_S3L_SHUTDOWNMESSAGE_H_
