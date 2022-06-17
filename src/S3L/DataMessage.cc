#include "DataMessage.h"
#include "../Crypto/api.hh"
#include "S3LHeader.h"
#include "SizeCalculator.h"
#include "constants.h"
#include "../util.h"

NetworkBuffer DataMessage::Serialize() const {
  return NetworkBuffer{} << rh << bytes_length << bytes << mac;
}

size_t DataMessage::GetTotalSize() const {
  return SizeCalculator{} << bytes_length << bytes << mac;
}

bool DataMessage::VerifyContent(u32 sequence_number) const {
  return rh.sequence_number == sequence_number;
}

std::shared_ptr<DataMessage> DataMessage::Deserialize(
    const S3LHeader &rh, const Vec<u8> &content_bytes) {
  auto rv = std::make_shared<DataMessage>(rh);
  auto network_buffer = NetworkBuffer{};
  network_buffer << content_bytes;
  network_buffer >> rv->bytes_length;
  rv->bytes = network_buffer.PopBytes(rv->bytes_length);
  network_buffer >> rv->mac;
  assert(rv->rh.length == rv->GetTotalSize());
  return rv;
}

DataMessage DataMessage::Create(const Vec<u8> &v, u32 sequence_number) {
  auto r = DataMessage{};
  r.bytes_length = numeric_cast<decltype(r.bytes_length)>(v.size());
  r.bytes = v;
  r.rh = S3LHeader{kData, numeric_cast<u16>(r.GetTotalSize()), sequence_number};
  return r;
}
