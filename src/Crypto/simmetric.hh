#ifndef CRYPTO_SIMMETRIC_H
#define CRYPTO_SIMMETRIC_H

#include "../util.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "error.hh"

namespace crypto {

template<const EVP_CIPHER *(*MODE)()>
struct AESEncrypt {
  EVP_CIPHER_CTX *ctx_;

  AESEncrypt(const ByteArray auto &key, const ByteArray auto &iv) {
    assert((ulong) EVP_CIPHER_iv_length(MODE()) == iv.size());
    assert((ulong) EVP_CIPHER_key_length(MODE()) == key.size());

    ctx_ = EVP_CIPHER_CTX_new();
	OPENSSLCHECKALLOC(ctx_);
    OPENSSLCHECK(EVP_EncryptInit_ex(ctx_, MODE(), nullptr, key.data(), iv.data()));
  }

  Vec<u8> Update(const ByteArray auto &data) {
    auto ciphertext = Vec<u8>(data.size());
    int ciphertextlen;
    OPENSSLCHECK(EVP_EncryptUpdate(ctx_, ciphertext.data(), &ciphertextlen, data.data(), data.size()));

    ciphertext.resize(ciphertextlen);

    return ciphertext;
  }

  Vec<u8> Final() {
    auto ciphertext = Vec<u8>(EVP_CIPHER_block_size(MODE()));
    int ciphertextlen;
    OPENSSLCHECK(EVP_EncryptFinal(ctx_, ciphertext.data(), &ciphertextlen));

    ciphertext.resize(ciphertextlen);

    return ciphertext;
  }

  ~AESEncrypt() {
    EVP_CIPHER_CTX_free(ctx_);
  }

  static Vec<u8> Make(const ByteArray auto &data,
                      const ByteArray auto &key,
                      const ByteArray auto &iv) {
    auto aes = AESEncrypt<MODE>(key, iv);
    auto rv = aes.Update(data);
    auto tmp = aes.Final();
    rv.insert(rv.end(), tmp.begin(), tmp.end());
    return rv;
  }
};

template<const EVP_CIPHER *(*MODE)()>
struct AESDecrypt {
  EVP_CIPHER_CTX *ctx_;

  AESDecrypt(const ByteArray auto &key, const ByteArray auto &iv) {
    assert((ulong) EVP_CIPHER_iv_length(MODE()) == iv.size());
    assert((ulong) EVP_CIPHER_key_length(MODE()) == key.size());

    ctx_ = EVP_CIPHER_CTX_new();
	OPENSSLCHECKALLOC(ctx_);
    OPENSSLCHECK(EVP_DecryptInit_ex(ctx_, MODE(), nullptr, key.data(), iv.data()));
  }

  Vec<u8> Update(const ByteArray auto &data) {
    auto plaintext = Vec<u8>(data.size());
    int plaintextlen;
    OPENSSLCHECK(EVP_DecryptUpdate(ctx_, plaintext.data(), &plaintextlen, data.data(), data.size()));

    plaintext.resize(plaintextlen);

    return plaintext;
  }

  Vec<u8> Final() {
    Vec<u8> plaintext(EVP_CIPHER_block_size(MODE()));
    int plaintextlen;
    OPENSSLCHECK(EVP_DecryptFinal(ctx_, plaintext.data(), &plaintextlen));

    plaintext.resize(plaintextlen);

    return plaintext;
  }

  ~AESDecrypt() {
    EVP_CIPHER_CTX_free(ctx_);
  }

  static Vec<u8> Make(const ByteArray auto &data,
                      const ByteArray auto &key,
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
} // /crypto

#endif // /CRYPTO_SIMMETRIC_H
