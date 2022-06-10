#ifndef UNTITLED2_NETWORKBUFFER_H
#define UNTITLED2_NETWORKBUFFER_H

#include "util.h"
#include <array>
#include <concepts>
#include <iostream>
#include <numeric>
#include <vector>

struct NetworkBuffer {
  std::deque<u8> buffer_{};

  NetworkBuffer() = default;

  NetworkBuffer(const NetworkBuffer&) = default;

  NetworkBuffer(NetworkBuffer&&) = default;

  explicit NetworkBuffer(const auto& iterable)
      : NetworkBuffer(iterable.begin(), iterable.end()) {}

  NetworkBuffer(std::input_iterator auto begin, std::input_iterator auto end) {
    auto n = end - begin;
    buffer_ = std::deque<u8>(n);
    auto scan = begin;
    for (decltype(n) i = 0; i < n; i++) {
      buffer_[i] = *scan;
      ++scan;
    }
  }
  operator Vec<u8>() { return Data<Vec<u8>>(); }

  void Push(std::integral auto n) {
    static_assert(sizeof(n) <= std::numeric_limits<int>::max());
    auto v = Vec<u8>{};
    for (int i = sizeof(n) - 1; i >= 0; --i) {
      v.push_back((n >> (8 * i)) & 0xff);
    }
    Push(v);
  }
  template <std::integral T, size_t n>
  void Push(const std::array<T, n>& arr) {
    buffer_.insert(buffer_.end(), arr.begin(), arr.end());
  }

  template <std::integral T>
  void Push(const Vec<T>& vec) {
    buffer_.insert(buffer_.end(), vec.begin(), vec.end());
  }

  template <std::integral T, size_t n>
  std::array<T, n> PopArray() {
    if (n > buffer_.size()) {
      throw std::runtime_error{"invalid size"};
    }
    std::array<T, n> arr{};
    for (size_t i = 0; i < n; i++) {
      arr[i] = buffer_[i];
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + n);
    return arr;
  }

  Vec<u8> PopBytes(size_t n) { return PopVec<u8>(n); }

  /// TODO: questo funziona solo con u8, estendere questa possibilita`
  template <std::integral T>
  Vec<T> PopVec(size_t n) {
    // TODO extend this possibility
    if (n > buffer_.size()) {
      throw std::runtime_error{"invalid size"};
    }
    Vec<T> arr(n);
    for (size_t i = 0; i < n; i++) {
      arr[i] = buffer_[i];
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + n);
    return arr;
  }

  template <std::integral T>
  T PopInteger() {
    // TODO extend this possibility
    // TODO add check
    auto v = PopVec<T>(sizeof(T));
    T rv{};
    for (size_t i = 0; i < sizeof(T); ++i) {
      T n = v.back();
      v.pop_back();
      rv |= (n << (8 * i));
    }
    return rv;
  }
  [[nodiscard]] const std::deque<u8>& Data() const noexcept { return buffer_; }

  template <typename T>
  T Data() const {
    return T(buffer_.begin(), buffer_.end());
  }

  friend NetworkBuffer& operator<<(NetworkBuffer& network_stream,
                                   const auto& n) {
    network_stream.Push(n);
    return network_stream;
  }

  friend NetworkBuffer& operator<<(NetworkBuffer&& network_stream,
                                   const auto& n) {
    network_stream.Push(n);
    return network_stream;
  }

  template <std::integral T, size_t n>
  friend NetworkBuffer& operator<<(NetworkBuffer& network_stream,
                                   const std::array<T, n>& arr) {
    network_stream.Push(arr);
    return network_stream;
  }

  friend NetworkBuffer& operator>>(NetworkBuffer& network_stream,
                                   std::integral auto& n) {
    n = network_stream.PopInteger<std::decay_t<decltype(n)>>();
    return network_stream;
  }

  template <std::integral T, size_t n>
  friend NetworkBuffer& operator>>(NetworkBuffer& network_stream,
                                   std::array<T, n>& arr) {
    arr = network_stream.template PopArray<T, n>();
    return network_stream;
  }

  template <std::integral T, size_t n>
  friend NetworkBuffer& operator<<(NetworkBuffer&& network_stream,
                                   const std::array<T, n>& arr) {
    return network_stream << arr;
  }

  friend NetworkBuffer& operator>>(NetworkBuffer&& network_stream,
                                   std::integral auto& n) {
    return network_stream >> n;
  }

  template <std::integral T, size_t n>
  friend NetworkBuffer& operator>>(NetworkBuffer&& network_stream,
                                   std::array<T, n>& arr) {
    return network_stream >> arr;
  }
};

#endif  // UNTITLED2_NETWORKBUFFER_H
