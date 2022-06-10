#ifndef S3L_UTIL_HH
#define S3L_UTIL_HH
#include "S3L/constants.h"
#include <iostream>
#include "util.h"
#include "crypto.hh"
#include "hash.hh"

namespace crypto {

template<typename Container = std::array<u8, kSha256Length>>
inline Container Sha256(const Vec<u8> &v) {
  auto digest = crypto::SHA256::Make(v);
  assert(digest.size() == kSha256Length);
  auto rv = Container{};
  std::copy(digest.begin(),
            digest.begin() + kSha256Length,
            rv.begin());
  return rv;
}

inline auto Mac(const ByteArray auto &v, const ByteArray auto &key) -> std::array<u8, kMacLength> {
  auto mac = HMAC::Make(key, v);
  auto rv = std::array<u8, kMacLength>{};
  std::copy(mac.begin(), mac.end(), rv.begin());
  return rv;
}


inline Vec<u8> ReadCertificate(const std::string &path) {
  auto cert = crypto::X509_mng(path.c_str());
  return cert.ToBytes();
}



inline Vec<u8> ExtractPublicKey(const Vec<u8> &certificate) {
  return X509_mng{certificate}.GetPubkeyAsBytes();
}

inline bool CertificateIsValid(const Vec<u8> &cert, const std::string &root_ca_path) {
  auto root = crypto::X509_mng(root_ca_path);
  auto store = crypto::X509_Store_mng();
  store.AddCert(root);
  auto tmp = crypto::X509_mng(cert);
  return store.VerifyCert(tmp);
}

}
#endif // S3L_UTIL_H