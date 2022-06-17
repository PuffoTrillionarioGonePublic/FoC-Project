#include "SocketChannel.h"

Vec<u8> SocketChannel::Read(size_t n) {
  size_t bytes_read = 0;
  auto v = Vec<u8>(n);
  do {
    auto buf = ::boost::asio::buffer(v.data() + bytes_read, n - bytes_read);
    size_t tmp = sd_->read_some(buf);
    bytes_read += tmp;
  } while (bytes_read < n);
  return v;
}

void SocketChannel::Write(const Vec<u8> &v) {
  size_t bytes_written = 0;
  do {
    auto buf = ::boost::asio::buffer(v.data() + bytes_written,
                                     v.size() - bytes_written);
    size_t tmp = sd_->write_some(buf);
    bytes_written += tmp;
  } while (bytes_written < v.size());
}
