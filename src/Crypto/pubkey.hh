#ifndef CRYPTO_PUBKEY_H
#define CRYPTO_PUBKEY_H

//#include "../crypto_api.hh"
#include "../util.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "error.hh"

namespace crypto {

inline auto PubKeyFromBytes(const ByteArray auto &v) {
  BIO *bio = BIO_new(BIO_s_mem());
  OPENSSLCHECKALLOC(bio);
  auto biobox = BIO_Box(bio, BIO_free);

  BIO_write(biobox.get(), v.data(), v.size());
  auto pubkey = PEM_read_bio_PUBKEY(biobox.get(), nullptr, nullptr, nullptr);
  OPENSSLCHECKALLOC(pubkey);
  return std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>{pubkey, EVP_PKEY_free};
}

inline auto PrivKeyFromBytes(const ByteArray auto &v) {
  BIO *bio = BIO_new(BIO_s_mem());
  OPENSSLCHECKALLOC(bio);
  auto biobox = BIO_Box(bio, BIO_free);

  BIO_write(biobox.get(), v.data(), v.size());
  auto pubkey = PEM_read_bio_PrivateKey(biobox.get(), nullptr, nullptr, nullptr);
  OPENSSLCHECKALLOC(pubkey);
  return std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>{pubkey, EVP_PKEY_free};
}
struct Signature {
  EVP_MD_CTX *ctx_;

  Signature() {
    ctx_ = EVP_MD_CTX_new();
	OPENSSLCHECKALLOC(ctx_);
    const EVP_MD *md = EVP_sha256(); // TODO: make it customizable
    OPENSSLCHECK(EVP_SignInit(ctx_, md));
  }

  Signature &Update(const u8 *data, size_t len) {
    OPENSSLCHECK(EVP_SignUpdate(ctx_, data, len));
    return *this;
  }

  Signature &Update(const ByteArray auto &data) {
    return Update(data.data(), data.size());
  }

  Vec<u8> Sign(EVP_PKEY *privkey) const {
    auto sign = Vec<u8>(EVP_PKEY_size(privkey));
    uint signlen;
    OPENSSLCHECK(EVP_SignFinal(ctx_, sign.data(), &signlen, privkey));

    assert(sign.size() == signlen);
    return sign;
  }

  ~Signature() {
    EVP_MD_CTX_free(ctx_);
  }

  static Vec<u8> Make2(EVP_PKEY *privkey, const ByteArray auto &data) {
    return Signature().Update(data).Sign(privkey);
  }

  static Vec<u8> Make(const ByteArray auto prv_key, const ByteArray auto &data) {
    auto tmp = PrivKeyFromBytes(prv_key);
    return Make2(tmp.get(), data);
  }

};

struct SignatureVerification {
  EVP_MD_CTX *ctx_;

  SignatureVerification() {
    ctx_ = EVP_MD_CTX_new();
	OPENSSLCHECKALLOC(ctx_);
    const EVP_MD *md = EVP_sha256();
    OPENSSLCHECK(EVP_VerifyInit(ctx_, md));
  }

  SignatureVerification &Update(const u8 *data, size_t len) {
    OPENSSLCHECK(EVP_VerifyUpdate(ctx_, data, len));
    return *this;
  }

  SignatureVerification &Update(const ByteArray auto &data) {
    return Update(data.data(), data.size());
  }

  bool Verify(const ByteArray auto &sig, EVP_PKEY *pubkey) {
    int res = EVP_VerifyFinal(ctx_, sig.data(), sig.size(), pubkey);

    if (res == -1)
      throw std::runtime_error("Error in signature verification");

    return res == 1;
  }

  ~SignatureVerification() {
    EVP_MD_CTX_free(ctx_);
  }

  static bool Make(EVP_PKEY *pubkey, const ByteArray auto &data, const ByteArray auto &sig) {
    return SignatureVerification().Update(data).Verify(sig, pubkey);
  }

  static bool Make(const ByteArray auto &pubkey,
                   const ByteArray auto &data,
                   const ByteArray auto &sig) {
    auto pubkey_box = PubKeyFromBytes(pubkey);
    return Make(pubkey_box.get(), data, sig);
  }
};

struct PKEYEncrypt {
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_encrypt.html

  EVP_PKEY_CTX *ctx_;

  explicit PKEYEncrypt(EVP_PKEY *pubkey) {
    ctx_ = EVP_PKEY_CTX_new(pubkey, nullptr);
    OPENSSLCHECK(EVP_PKEY_encrypt_init(ctx_));
    OPENSSLCHECK(EVP_PKEY_CTX_set_rsa_padding(ctx_, RSA_PKCS1_OAEP_PADDING));
  }

  Vec<u8> Encrypt(const ByteArray auto &data) {
    size_t outlen;

    // determine buffer length
    OPENSSLCHECK(EVP_PKEY_encrypt(ctx_, nullptr, &outlen, data.data(), data.size()));

    auto out = Vec<u8>(outlen);
    OPENSSLCHECK(EVP_PKEY_encrypt(ctx_, out.data(), &outlen, data.data(), data.size()));

    return out;
  }

  ~PKEYEncrypt() {
    EVP_PKEY_CTX_free(ctx_);
  }

  static Vec<u8> Make(EVP_PKEY *pubkey, const ByteArray auto &data) {
    return PKEYEncrypt(pubkey).Encrypt(data);
  }

  static Vec<u8> Make(const ByteArray auto &pubkey, const ByteArray auto &data) {
    auto pub = PubKeyFromBytes(pubkey);
    return Make(pub.get(), data);
  }
};

struct PKEYDecrypt {
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_decrypt.html

  EVP_PKEY_CTX *ctx_;

  explicit PKEYDecrypt(EVP_PKEY *privkey) {
    ctx_ = EVP_PKEY_CTX_new(privkey, nullptr);
    OPENSSLCHECK(EVP_PKEY_decrypt_init(ctx_));
    OPENSSLCHECK(EVP_PKEY_CTX_set_rsa_padding(ctx_, RSA_PKCS1_OAEP_PADDING));
  }

  Vec<u8> Decrypt(const ByteArray auto &data) const {
    size_t outlen;

    // determine buffer length
    OPENSSLCHECK(EVP_PKEY_decrypt(ctx_, nullptr, &outlen, data.data(), data.size()));

    auto out = Vec<u8>(outlen);
    OPENSSLCHECK(EVP_PKEY_decrypt(ctx_, out.data(), &outlen, data.data(), data.size()));

    out.resize(outlen);

    return out;
  }

  ~PKEYDecrypt() {
    EVP_PKEY_CTX_free(ctx_);
  }

  static Vec<u8> Make(EVP_PKEY *privkey, const ByteArray auto &data) {
    return PKEYDecrypt(privkey).Decrypt(data);
  }
};

inline EVP_PKEY_Box PubkeyFromFile(const std::string &path) {
  FILE *f = fopen(path.c_str(), "rb");
  EVP_PKEY *rv;

  if (f == nullptr) {
    throw std::runtime_error("Error opening pubkey file");
  }
  auto f_box = std::unique_ptr<FILE, decltype(&fclose)>(f, fclose);

  rv = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
  OPENSSLCHECKALLOC(rv);

  return {rv, EVP_PKEY_free};
}

inline Vec<u8> PubkeyFromFileAsBytes(const std::string &path) {
  BIO *bio = BIO_new(BIO_s_mem());
  OPENSSLCHECKALLOC(bio);
  auto biobox = BIO_Box(bio, BIO_free);
  auto pub_key = PubkeyFromFile(path);
  OPENSSLCHECK(PEM_write_bio_PUBKEY(biobox.get(), pub_key.get()));
  u8 *ptr;
  i64 size = BIO_get_mem_data(biobox.get(), &ptr);
  return Vec<u8>(ptr, ptr + size);
}

inline EVP_PKEY_Box PrivkeyFromFile(const char *path) {
  FILE *f = fopen(path, "rb");
  EVP_PKEY *rv;

  if (f == nullptr) {
    throw std::runtime_error("Error opening pubkey file");
  }
  auto f_box = std::unique_ptr<FILE, decltype(&fclose)>(f, fclose);

  rv = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
  OPENSSLCHECKALLOC(rv);

  return {rv, EVP_PKEY_free};
}

inline SecVec<u8> PrivkeyFromFileAsBytes(const char *path) {
  BIO *bio = BIO_new(BIO_s_mem());
  OPENSSLCHECKALLOC(bio);
  auto biobox = BIO_Box(bio, BIO_free);
  auto prv_key = PrivkeyFromFile(path);
  OPENSSLCHECK(PEM_write_bio_PrivateKey(biobox.get(),
                                        prv_key.get(),
                                        nullptr,
                                        nullptr,
                                        0,
                                        nullptr,
                                        nullptr));
  u8 *ptr;
  i64 size = BIO_get_mem_data(biobox.get(), &ptr);
  auto rv = SecVec<u8>(ptr, ptr + size);
  return rv;
}

inline SecVec<u8> PrivkeyFromFileAsBytes(const std::string &path) {
  return PrivkeyFromFileAsBytes(path.c_str());
}

} // /namespace crypto

#endif // /CRYPTO_PUBKEY_H
