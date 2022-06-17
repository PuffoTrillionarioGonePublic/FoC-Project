#ifndef S3L_LocalChannel_H
#define S3L_LocalChannel_H

#include "IOChannel.h"
#include "constants.h"
#include "../util.h"
#include <sys/socket.h>
#include <barrier>
#include <condition_variable>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <unistd.h>

class LocalChannel : public IOChannel {
  int sockets[2];
  std::optional<size_t> first_thread{};
  std::optional<size_t> second_thread{};

  size_t GetIndex() {
    auto h = std::hash<std::thread::id>{}(std::this_thread::get_id());
    if (h == first_thread) {
      return 0;
    }
    if (h == second_thread) {
      return 1;
    }
    throw std::runtime_error{"Thread isn't registered"};
  }

  int GetSocket() { return sockets[GetIndex()]; }

  void RegisterCurrentThread() {
    auto h = std::hash<std::thread::id>{}(std::this_thread::get_id());
    if (!first_thread) {
      first_thread = h;
    } else if (!second_thread) {
      second_thread = h;
    } else {
      // throw std::runtime_error{"Can't register other threads"};
    }
  }

  bool IsClosed_() {
    /// TODO: this function
    return false;
  }

  void Close_() noexcept {
    close(sockets[0]);
    close(sockets[1]);
  }

  static std::shared_ptr<LocalChannel> instance_;

 public:
  LocalChannel() {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
      throw std::runtime_error{"opening stream socket pair failed"};
    }
  }

  static std::shared_ptr<LocalChannel> Create() {
    if (LocalChannel::instance_ == nullptr) {
      instance_ = std::make_shared<LocalChannel>();
    }
    return instance_;
  }

  Vec<u8> Read(size_t n) override {
    RegisterCurrentThread();
    ssize_t bytes_read = 0;
    auto v = Vec<u8>(n);
    do {
      ssize_t tmp = read(GetSocket(), v.data() + bytes_read, n - bytes_read);
      if (tmp < 0) {
        throw std::runtime_error{"writing stream message failed"};
      }
      bytes_read += tmp;
    } while (bytes_read < n);

    return v;
  }

  void Write(const Vec<u8> &v) override {
    RegisterCurrentThread();
    size_t bytes_written = 0;
    do {
      size_t tmp = write(GetSocket(), v.data() + bytes_written,
                         v.size() - bytes_written);
      bytes_written += tmp;
    } while (bytes_written < v.size());
  }

  bool IsClosed() override {
    /// TODO: this function
    return IsClosed_();
  }

  void Close() noexcept override { Close_(); }

  ~LocalChannel() override {
    /// Do not invoke virtual member functions from destructor
    if (IsClosed_()) {
      return;
    }
    Close_();
  }
};
std::shared_ptr<LocalChannel> LocalChannel::instance_ = nullptr;

#endif  // S3L_LocalChannel_H
