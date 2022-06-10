#include "DataMessage.h"
#include "Crypto/api.hh"
#include "S3L/constants.h"
#include "util.h"

DataMessage DataMessage::From(const Vec<u8>& v) {
  auto data_message = DataMessage{};
  data_message.bytes = v;
  data_message.rh.length = v.size() + kMacLength;
  return data_message;
}

NetworkBuffer DataMessage::Serialize() const {
  return NetworkBuffer{} << rh << bytes << mac;
}

bool DataMessage::VerifyContent(u32 sequence_number) const {
  return rh.sequence_number == sequence_number;
}

std::shared_ptr<DataMessage> DataMessage::Deserialize(
    const S3LHeader& rh, const Vec<u8>& content_bytes) {
  auto network_buffer = NetworkBuffer{content_bytes};
  auto rv = std::make_shared<DataMessage>(rh);
  /// TODO cambiare assolutamente questa parte
  auto v = network_buffer.PopBytes(rh.length - kMacLength);
  rv->bytes = v;
  rv->rh.length = v.size() + kMacLength;
  network_buffer >> rv->mac;
  return rv;
}

DataMessage DataMessage::Create(const Vec<u8>& v, u32 sequence_number) {
  auto r = DataMessage{};
  auto message_size = v.size() + kMacLength;
  r.rh = S3LHeader{kData, numeric_cast<u16>(message_size), sequence_number};
  r.bytes = v;
  r.rh.length = v.size() + kMacLength;
  return r;
}
