#include "S3LHeader.h"

S3LHeader::S3LHeader(u8 content_type, u16 length, u32 sequence_number,
                     u8 version)
    : content_type{content_type},
      length{length},
      version{version},
      sequence_number{sequence_number} {}

NetworkBuffer S3LHeader::Serialize() const {
  auto network_buffer = NetworkBuffer{};
  return network_buffer << *this;
}
