#ifndef CRYPTO_SIMMETRIC_H
#define CRYPTO_SIMMETRIC_H

#include "../util.h"
#include "error.hh"
#include <openssl/aes.h>
#include <openssl/evp.h>

namespace crypto {

template <const EVP_CIPHER *(*MODE)()>
struct AESEncrypt {
  EVP_CIPHER_CTX *ctx_{};

  AESEncrypt() = default;
  AESEncrypt(const AESEncrypt&) = delete;
  AESEncrypt(AESEncrypt&& other)
  : ctx_{other.ctx_}
  {
    other.ctx_ = nullptr;
  }
  AESEncrypt& operator=(const AESEncrypt& other) = delete;
  AESEncrypt& operator=(AESEncrypt&& other) {
    ctx_ = other.ctx_;
    other.ctx_ = nullptr;
    return *this;
  }
  AESEncrypt(const ByteArray auto &key, const ByteArray auto &iv) {
    assert((ulong)EVP_CIPHER_iv_length(MODE()) == iv.size());
    assert((ulong)EVP_CIPHER_key_length(MODE()) == key.size());

    ctx_ = EVP_CIPHER_CTX_new();
    OPENSSLCHECKALLOC(ctx_);
    OPENSSLCHECK(
        EVP_EncryptInit_ex(ctx_, MODE(), nullptr, key.data(), iv.data()));
  }

  Vec<u8> Update(const ByteArray auto &data) {
    assert(ctx_ != nullptr);
    auto ciphertext = Vec<u8>(data.size());
    int ciphertextlen;
    OPENSSLCHECK(EVP_EncryptUpdate(ctx_, ciphertext.data(), &ciphertextlen,
                                   data.data(), data.size()));

    ciphertext.resize(ciphertextlen);

    return ciphertext;
  }

  Vec<u8> Final() {
    assert(ctx_ != nullptr);
    auto ciphertext = Vec<u8>(EVP_CIPHER_block_size(MODE()));
    int ciphertextlen;
    OPENSSLCHECK(EVP_EncryptFinal(ctx_, ciphertext.data(), &ciphertextlen));

    ciphertext.resize(ciphertextlen);

    return ciphertext;
  }

  ~AESEncrypt() {
    if (ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  static Vec<u8> Make(const ByteArray auto &data, const ByteArray auto &key,
                      const ByteArray auto &iv) {
    auto aes = AESEncrypt<MODE>(key, iv);
    auto rv = aes.Update(data);
    auto tmp = aes.Final();
    rv.insert(rv.end(), tmp.begin(), tmp.end());
    return rv;
  }
};

template <const EVP_CIPHER *(*MODE)()>
struct AESDecrypt {
  EVP_CIPHER_CTX *ctx_{};
  AESDecrypt() = default;
  AESDecrypt(const AESDecrypt&) = delete;
  AESDecrypt(AESDecrypt&& other)
  : ctx_{other.ctx_}
  {
    other.ctx_ = nullptr;
  }
  AESDecrypt& operator=(const AESDecrypt& other) = delete;
  AESDecrypt& operator=(AESDecrypt&& other) {
    ctx_ = other.ctx_;
    other.ctx_ = nullptr;
    return *this;
  }

  AESDecrypt(const ByteArray auto &key, const ByteArray auto &iv) {
    assert((ulong)EVP_CIPHER_iv_length(MODE()) == iv.size());
    assert((ulong)EVP_CIPHER_key_length(MODE()) == key.size());

    ctx_ = EVP_CIPHER_CTX_new();
    OPENSSLCHECKALLOC(ctx_);
    OPENSSLCHECK(
        EVP_DecryptInit_ex(ctx_, MODE(), nullptr, key.data(), iv.data()));
  }

  Vec<u8> Update(const ByteArray auto &data) {
    assert(ctx_ != nullptr);
    auto plaintext = Vec<u8>(data.size());
    int plaintextlen;
    OPENSSLCHECK(EVP_DecryptUpdate(ctx_, plaintext.data(), &plaintextlen,
                                   data.data(), data.size()));

    plaintext.resize(plaintextlen);

    return plaintext;
  }

  Vec<u8> Final() {
    assert(ctx_ != nullptr);
    Vec<u8> plaintext(EVP_CIPHER_block_size(MODE()));
    int plaintextlen;
    OPENSSLCHECK(EVP_DecryptFinal(ctx_, plaintext.data(), &plaintextlen));

    plaintext.resize(plaintextlen);

    return plaintext;
  }

  ~AESDecrypt() {
    if (ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  static Vec<u8> Make(const ByteArray auto &data, const ByteArray auto &key,
                      const ByteArray auto &iv) {
    auto aes = AESDecrypt<MODE>(key, iv);
    auto rv = aes.Update(data);
    auto tmp = aes.Final();
    rv.insert(rv.end(), tmp.begin(), tmp.end());
    return rv;
  }
};

using AESEncrypt128CTR = AESEncrypt<EVP_aes_128_ctr>;
using AESDecrypt128CTR = AESDecrypt<EVP_aes_128_ctr>;
}  // namespace crypto

#endif  // /CRYPTO_SIMMETRIC_H
