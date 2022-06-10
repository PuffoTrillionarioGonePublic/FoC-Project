#ifndef CRYPTO_RANDOM_H
#define CRYPTO_RANDOM_H

//#include "../crypto_api.hh"
#include <openssl/rand.h>
#include "../util.h"
#include "error.hh"

namespace crypto {

template<typename Container = Vec<u8>>
inline Container RandomBytes(size_t n) {
  auto rv = Container(n);
  OPENSSLCHECK(RAND_bytes(rv.data(), n));
  return rv;
}

template<size_t N, typename Container = std::array<u8, N>>
inline Container GenerateRandomBytes() {
  static_assert(N <= std::numeric_limits<int>::max());
  auto rv = Container{};
  OPENSSLCHECK(RAND_bytes(rv.data(), N));
  return rv;
}

} // /namespace crypto

#endif // /CRYPTO_RANDOM_H
