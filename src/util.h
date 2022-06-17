#ifndef S3L_UTIL_H
#define S3L_UTIL_H

#include "S3L/constants.h"

#include <openssl/crypto.h>
#include <boost/format.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <deque>
#include <functional>
#include <iostream>
#include <regex>

using boost::numeric_cast;

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

inline void secure_scrub_memory_func(void *ptr, size_t n) {
  volatile auto *p = reinterpret_cast<volatile uint8_t *>(ptr);
  for (size_t i = 0; i != n; ++i) p[i] = 0;
}

static void (*volatile secure_scrub_memory_ptr)(void *, size_t) =
    secure_scrub_memory_func;

inline void secure_scrub_memory(void *ptr, size_t n) {
  secure_scrub_memory_ptr(ptr, n);
}

template <typename T>
inline void secure_scrub_memory(T &t) {
  secure_scrub_memory(&t, sizeof(t));
}

template <typename T>
class secure_allocator {
 public:
  /**
   * Assert exists to prevent someone from doing something that will
   * probably crash anyway (like secure_vector<non_POD_t> where ~non_POD_t
   * deletes a member pointer which was zeroed before it ran).
   */
  static_assert(std::is_integral<T>::value,
                "secure_allocator supports only integer types");
  typedef T value_type;
  typedef std::size_t size_type;

  secure_allocator() noexcept = default;

  secure_allocator(const secure_allocator &) noexcept = default;

  secure_allocator &operator=(const secure_allocator &) noexcept = default;

  ~secure_allocator() noexcept = default;

  template <typename U>
  secure_allocator(const secure_allocator<U> &) noexcept {}

  T *allocate(std::size_t n) {
    return static_cast<T *>(operator new(n * sizeof(T)));
  }

  void deallocate(T *p, std::size_t n) {
    if (p == nullptr) return;

    secure_scrub_memory(p, n * sizeof(T));
    ::operator delete(p);
  }
};


template <typename T, typename U>
inline bool operator==(const secure_allocator<T> &,
                       const secure_allocator<U> &) {
  return true;
}

template <typename T, typename U>
inline bool operator!=(const secure_allocator<T> &,
                       const secure_allocator<U> &) {
  return false;
}

template <typename T>
using secure_vector = std::vector<T, secure_allocator<T>>;

template <typename T, typename A = std::allocator<T>>
using Vec = std::vector<T, A>;

template <typename T>
using SecVec = secure_vector<T>;

inline Vec<u8> operator"" _u8(const char *str, size_t length) {
  return Vec<u8>(str, str + length);
}


template<std::integral T>
inline auto operator==(const SecVec<T> &, const SecVec<T> &) {
  static_assert(sizeof(T) == 0);
}

template <std::integral T, size_t N>
bool AreEqual(const std::array<T, N> &arr1, const std::array<T, N> & arr2) {
  return arr1 == arr2;
}


template<std::integral T, size_t N>
constexpr inline auto operator==(const std::array<T, N> &, const std::array<T, N> &) {
  static_assert(sizeof(T) == 0);
}





template <std::integral T, size_t N>
struct SecArray : public std::array<T, N> {
  ~SecArray() { explicit_bzero(this, N); }
};






template<std::integral T, size_t N>
inline auto operator==(const SecArray<T, N> &, const SecArray<T, N> &) {
  static_assert(sizeof(T) == 0);
}



template <typename T>
concept ByteArray = std::ranges::range<T> && requires(T &t) {
  {t.data()};
  {sizeof(*t.data()) == 1};
};

template <size_t N>
bool AreSecureEqual(const std::array<u8, N> &arr1, const std::array<u8, N> &arr2) {
  return CRYPTO_memcmp(arr1.data(), arr2.data(), N) == 0;
}

template <size_t N>
bool AreSecureEqual(const SecArray<u8, N> &arr1, const SecArray<u8, N> &arr2) {
  return CRYPTO_memcmp(arr1.data(), arr2.data(), N) == 0;
}

bool AreSecureEqual(const ByteArray auto &arr1, const ByteArray auto &arr2) {
  if (arr1.size() != arr2.size())
    return false;
  return CRYPTO_memcmp(arr1.data(), arr2.data(), arr1.size()) == 0;
}

bool AreEqual(const ByteArray auto &arr1, const ByteArray auto &arr2) {
  if (arr1.size() != arr2.size())
    return false;
  return std::memcmp(arr1.data(), arr2.data(), arr1.size()) == 0;
}



template <size_t FirstSize, size_t SecondSize, size_t N>
inline auto SplitArray(const std::array<u8, N> &arr)
    -> std::tuple<SecArray<u8, FirstSize>, SecArray<u8, SecondSize>> {
  static_assert(FirstSize == N - SecondSize);
  auto a1 = SecArray<u8, FirstSize>{};
  auto a2 = SecArray<u8, SecondSize>{};
  std::copy(arr.begin(), arr.begin() + FirstSize, a1.begin());
  std::copy(arr.begin() + FirstSize, arr.end(), a2.begin());
  return {a1, a2};
}

template <typename T, size_t N, size_t M>
inline auto Concat(const std::array<T, N> &arr1, const std::array<T, M> &arr2) {
  auto rv = std::array<T, N + M>{};
  for (size_t i = 0; i < N; i++) {
    rv[i] = arr1[i];
  }
  for (size_t i = 0; i < M; i++) {
    rv[N + i] = arr2[i];
  }
  return rv;
}

template <typename T = Vec<u8>>
inline auto Concat(const ByteArray auto &arr1, const ByteArray auto &arr2) {
  auto rv = T(arr1.begin(), arr1.end());
  rv.insert(rv.begin(), arr2.begin(), arr2.end());
  return rv;
}

inline std::ostream &operator<<(std::ostream &os, const Vec<u8> &v) {
  const char alpha[] = "0123456789abcdef";
  std::for_each(v.begin(), v.end(),
                [&](u8 scan) { os << alpha[scan >> 4] << alpha[scan & 0xf]; });
  return os;
}

template <size_t N>
inline std::ostream &operator<<(std::ostream &os, const std::array<u8, N> &v) {
  os << Vec<u8>(v.begin(), v.end());
  return os;
}

template <typename T, size_t N>
inline consteval size_t ArraySize(const std::array<T, N> &) {
  return N;
}




#endif  // S3L_UTIL_H