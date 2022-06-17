#include "ShutdownMessage.h"

NetworkBuffer ShutdownMessage::Serialize() const {
  return NetworkBuffer{} << rh << mac;
}

ShutdownMessage ShutdownMessage::Create() {
  auto r = ShutdownMessage{};
  r.rh = S3LHeader{kShutdown, numeric_cast<u16>(kMacLength)};
  return r;
}

std::shared_ptr<ShutdownMessage> ShutdownMessage::Deserialize(
    const S3LHeader &rh, const Vec<u8> &content_bytes) {
  auto network_buffer = NetworkBuffer{content_bytes};
  auto rv = std::make_shared<ShutdownMessage>(rh);
  network_buffer >> rv->mac;
  return rv;
}
