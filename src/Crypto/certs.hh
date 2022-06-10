#ifndef CRYPTO_CERTS_H
#define CRYPTO_CERTS_H

#include "../util.h"
#include "error.hh"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace crypto {

using X509_Box = std::unique_ptr<X509, decltype(&::X509_free)>;
using EVP_PKEY_Box = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_Box = std::unique_ptr<BIO, decltype(&::BIO_free)>;

// X509 cert managed
struct X509_mng {
  X509 *cert_;

  explicit X509_mng(const std::string &path) {
    FILE *f = fopen(path.c_str(), "rb");
    if (f == nullptr) {
      throw std::runtime_error("Error opening pubkey file");
    }

    cert_ = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    OPENSSLCHECKALLOC(cert_);
  }

  explicit X509_mng(const Vec<u8> &v) {
    BIO *bio = BIO_new(BIO_s_mem());
    OPENSSLCHECKALLOC(bio);
    auto biobox = BIO_Box(bio, BIO_free);

    BIO_write(biobox.get(), v.data(), v.size());
    cert_ = PEM_read_bio_X509(biobox.get(), nullptr, nullptr, nullptr);
    OPENSSLCHECKALLOC(cert_);
  }

  [[nodiscard]] X509 *get() const { return cert_; }

  [[nodiscard]] Vec<u8> ToBytes() const {
    BIO *bio = BIO_new(BIO_s_mem());
    OPENSSLCHECKALLOC(bio);
    auto biobox = BIO_Box(bio, BIO_free);

    PEM_write_bio_X509(biobox.get(), cert_);

    u8 *ptr;
    i64 size = BIO_get_mem_data(biobox.get(), &ptr);

    auto rv = Vec<u8>(ptr, ptr + size);

    return rv;
  }

  [[nodiscard]] EVP_PKEY_Box GetPubkey() const {
    EVP_PKEY *pubkey = X509_get_pubkey(cert_);
    OPENSSLCHECKALLOC(pubkey);
    return EVP_PKEY_Box{pubkey, EVP_PKEY_free};
  }

  [[nodiscard]] Vec<u8> GetPubkeyAsBytes() const {
    BIO *bio = BIO_new(BIO_s_mem());
    OPENSSLCHECKALLOC(bio);
    auto biobox = BIO_Box(bio, BIO_free);
    auto pubkey = GetPubkey();

    OPENSSLCHECK(PEM_write_bio_PUBKEY(biobox.get(), pubkey.get()));

    u8 *ptr;
    i64 size = BIO_get_mem_data(biobox.get(), &ptr);

    auto rv = Vec<u8>(ptr, ptr + size);

    return rv;
  }

  [[nodiscard]] std::string GetName() const {
    auto *subject_name = X509_get_subject_name(cert_);
    auto *name = X509_NAME_oneline(subject_name, nullptr, 0);
    OPENSSLCHECKALLOC(name);
    auto name_box = std::unique_ptr<char[], decltype(&::free)>(name, ::free);
    auto rv = std::string(name);
    return rv;
  }

  ~X509_mng() { X509_free(cert_); }
};

// X509 Store manages
struct X509_Store_mng {
  X509_STORE *store_;

  // without this i would leak memory upon store destruction
  Vec<X509_Box> CertVec;

  X509_Store_mng() {
    store_ = X509_STORE_new();
    OPENSSLCHECKALLOC(store_);
  }

  void AddCert(X509_mng &cert) {
    X509 *x = X509_dup(cert.get());
    OPENSSLCHECKALLOC(x);
    auto x_box = X509_Box(x, X509_free);
    OPENSSLCHECK(X509_STORE_add_cert(store_, x_box.get()));
    CertVec.push_back(std::move(x_box));
  }

  bool VerifyCert(X509_mng &cert) const {
    auto *ctx = X509_STORE_CTX_new();
    OPENSSLCHECKALLOC(ctx);
    auto ctx_box = std::unique_ptr<std::remove_pointer_t<decltype(ctx)>,
                                   decltype(&X509_STORE_CTX_free)>(
        ctx, X509_STORE_CTX_free);
    OPENSSLCHECK(
        X509_STORE_CTX_init(ctx_box.get(), store_, cert.get(), nullptr));
    auto rv = X509_verify_cert(ctx_box.get());
    OPENSSLGENERICTHROWIFTRUE(rv < 0);

    return rv != 0;
  }

  ~X509_Store_mng() { X509_STORE_free(store_); }
};

}  // namespace crypto

#endif  // /CRYPTO_CERTS_H
