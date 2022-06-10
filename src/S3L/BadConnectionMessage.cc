#include "BadConnectionMessage.h"

NetworkBuffer BadConnectionMessage::Serialize() const {
  return NetworkBuffer{} << rh;
}

auto BadConnectionMessage::Deserialize(const S3LHeader& rh,
                                       const Vec<u8>& content_bytes)
    -> std::shared_ptr<BadConnectionMessage> {
  auto network_buffer = NetworkBuffer{content_bytes};
  auto rv = std::make_shared<BadConnectionMessage>(rh);
  return rv;
}
