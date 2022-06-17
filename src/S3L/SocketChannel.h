#ifndef S3L_SOCKETCOMMUNICATION_H
#define S3L_SOCKETCOMMUNICATION_H

#include "IOChannel.h"
#include <boost/asio.hpp>

class SocketChannel : public IOChannel {
  std::shared_ptr<boost::asio::io_service> io_service_;
  std::shared_ptr<boost::asio::ip::tcp::socket> sd_;
  bool closed_ = false;

  void Close_() noexcept {
    if (!IsClosed_()) {
      try {
        sd_->close();
      } catch (...) {
      }
      closed_ = true;
    }
  };

  bool IsClosed_() const { return closed_; }

 public:
  explicit SocketChannel(std::shared_ptr<boost::asio::io_service> io_service,
                         std::shared_ptr<boost::asio::ip::tcp::socket> socket)
      : io_service_{std::move(io_service)}, sd_{std::move(socket)} {}

  Vec<u8> Read(size_t n) override;

  void Write(const Vec<u8> &v) override;

  bool IsClosed() override { return IsClosed_(); }

  void Close() noexcept override { Close_(); }

  ~SocketChannel() override { Close_(); }
};
#endif  // S3L_SOCKETCOMMUNICATION_H
