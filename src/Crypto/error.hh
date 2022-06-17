#ifndef CRYPTO_ERROR_H
#define CRYPTO_ERROR_H

#include <boost/format.hpp>
#include <openssl/err.h>

namespace crypto {

#define OPENSSLGENERICTHROWIFTRUE(x)                                     \
  x ? throw std::runtime_error(                                          \
          (boost::format("%1% in %3% (%4%:%5%) because %6%") % #x % "" % \
           __FUNCTION__ % __FILE__ % __LINE__ %                          \
           ERR_error_string(ERR_get_error(), nullptr))                   \
              .str())                                                    \
    : 0
#define OPENSSLCHECK(x) OPENSSLGENERICTHROWIFTRUE(x != 1)
#define OPENSSLCHECKALLOC(x) OPENSSLGENERICTHROWIFTRUE(x == nullptr)

};  // namespace crypto

#endif  // CRYPTO_ERROR_H