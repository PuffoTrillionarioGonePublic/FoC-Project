#ifndef FOC_PROJECT_SRC_S3L_DATAMESSAGE_H_
#define FOC_PROJECT_SRC_S3L_DATAMESSAGE_H_

#include "AuthenticatedEncryptedMessage.h"
#include "NetworkBuffer.h"
#include "constants.h"
#include "S3LMessage.h"
#include "../util.h"

struct DataMessage : public AuthenticatedEncryptedMessage {
  S3LHeader rh{};

  u16 bytes_length{};
  Vec<u8> bytes{};
  std::array<u8, kMacLength> mac{};

  DataMessage() : rh{kData, sizeof(mac)} {}

  explicit DataMessage(const S3LHeader &rh) : rh{rh} {}

  [[nodiscard]] NetworkBuffer Serialize() const override;

  [[nodiscard]] bool VerifyContent(u32 sequence_number) const;

  std::array<u8, kMacLength> &GetMac() override { return mac; }

  void SetMac(const std::array<u8, kMacLength> &m) override { mac = m; }

  Vec<u8> DataToMac() const { return NetworkBuffer{} << rh << bytes; }

  static std::shared_ptr<DataMessage> Deserialize(const S3LHeader &rh,
                                                  const Vec<u8> &content_bytes);
  size_t GetTotalSize() const;

  static DataMessage Create(const Vec<u8> &v, u32 sequence_number);
};

#endif  // FOC_PROJECT_SRC_S3L_DATAMESSAGE_H_
