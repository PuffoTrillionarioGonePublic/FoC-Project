#ifndef S3L_RECORDHEADER_H
#define S3L_RECORDHEADER_H
#include "NetworkBuffer.h"
#include "util.h"
NetworkBuffer& operator<<(NetworkBuffer&, const struct S3LHeader&);

struct S3LHeader final {
  u8 content_type;
  u16 length;
  u8 version;
  u32 sequence_number;

  S3LHeader() = default;

  static const size_t kBytesLength = sizeof(content_type) + sizeof(length) +
                                     sizeof(version) + sizeof(sequence_number);

  explicit S3LHeader(u8 content_type, u16 length = 0, u32 sequence_number = 0,
                     u8 version = 0);

  [[nodiscard]] NetworkBuffer Serialize() const;
};

inline NetworkBuffer& operator>>(NetworkBuffer& network_buffer, S3LHeader& r) {
  return network_buffer >> r.content_type >> r.length >> r.version >>
         r.sequence_number;
}

inline NetworkBuffer& operator<<(NetworkBuffer& network_buffer,
                                 const S3LHeader& r) {
  return network_buffer << r.content_type << r.length << r.version
                        << r.sequence_number;
}

inline NetworkBuffer& operator<<(NetworkBuffer&& network_buffer,
                                 const S3LHeader& r) {
  return network_buffer << r;
}

#endif  // S3L_RECORDHEADER_H
