#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include "../util.h"
#include "error.hh"
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace crypto {

template <const EVP_MD *(*MD)()>
struct HASH {
  EVP_MD_CTX *ctx_;
  const EVP_MD *md_;

  HASH() {
    ctx_ = EVP_MD_CTX_new();
    OPENSSLCHECKALLOC(ctx_);
    md_ = MD();
    OPENSSLCHECK(EVP_DigestInit(ctx_, md_));
  }

  HASH &Update(const u8 *data, size_t len) {
    OPENSSLCHECK(EVP_DigestUpdate(ctx_, data, len));
    return *this;
  }

  HASH &Update(const ByteArray auto &data) {
    return Update(data.data(), data.size());
  }

  template <ByteArray Container = Vec<u8>>
  Container Digest() {
    auto digest = Container(EVP_MD_size(md_));
    uint digestlen;
    OPENSSLCHECK(EVP_DigestFinal(ctx_, digest.data(), &digestlen));

    assert(digest.size() == digestlen);
    return digest;
  }

  ~HASH() { EVP_MD_CTX_free(ctx_); }

  template <ByteArray Container = Vec<u8>>
  static Container Make(const ByteArray auto &data) {
    return HASH<MD>().Update(data).template Digest<Container>();
  }
};

using SHA256 = HASH<EVP_sha256>;

using MD5 = HASH<EVP_md5>;

struct HMAC {
  HMAC_CTX *ctx_;
  const EVP_MD *md_;

  explicit HMAC(const ByteArray auto &key) {
    ctx_ = HMAC_CTX_new();
    OPENSSLCHECKALLOC(ctx_);
    md_ = EVP_sha256();
    OPENSSLCHECK(HMAC_Init_ex(ctx_, key.data(), key.size(), md_, nullptr));
  }

  HMAC &Update(const u8 *data, size_t len) {
    OPENSSLCHECK(HMAC_Update(ctx_, data, len));
    return *this;
  }

  HMAC &Update(const ByteArray auto &data) {
    return Update(data.data(), data.size());
  }

  Vec<u8> Digest() {
    auto digest = Vec<u8>(EVP_MD_size(md_));
    uint digestlen;
    OPENSSLCHECK(HMAC_Final(ctx_, digest.data(), &digestlen));

    assert(digest.size() == digestlen);
    return digest;
  }

  ~HMAC() { HMAC_CTX_free(ctx_); }

  static Vec<u8> Make(const ByteArray auto &key, const ByteArray auto &data) {
    return HMAC(key).Update(data).Digest();
  }
};

}  // namespace crypto

#endif  // /CRYPTO_HASH_H
