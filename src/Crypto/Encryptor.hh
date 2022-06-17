#ifndef ENCRYPTOR_HH
#define ENCRYPTOR_HH

#include "../util.h"
#include "simmetric.hh"

namespace crypto {

  struct AES128CTREncryptor {
    AESEncrypt128CTR enc;

    AES128CTREncryptor() = default;
    AES128CTREncryptor(const AES128CTREncryptor&) = delete;
    AES128CTREncryptor(AES128CTREncryptor&&) = default;

    AES128CTREncryptor& operator=(const AES128CTREncryptor&) = delete;
    AES128CTREncryptor& operator=(AES128CTREncryptor&&) = default;

    AES128CTREncryptor(const ByteArray auto &key, const ByteArray auto &iv) : enc{key, iv} { }

    Vec<u8> Encrypt(const ByteArray auto &v) {
      return enc.Update(v);
    }

    ~AES128CTREncryptor() = default;
  };


  struct AES128CTRDecryptor {
    AESDecrypt128CTR dec;

    AES128CTRDecryptor() = default;
    AES128CTRDecryptor(const AES128CTRDecryptor&) = delete;
    AES128CTRDecryptor(AES128CTRDecryptor&&) = default;

    AES128CTRDecryptor& operator=(const AES128CTRDecryptor&) = delete;
    AES128CTRDecryptor& operator=(AES128CTRDecryptor&&) = default;

    AES128CTRDecryptor(const ByteArray auto &key, const ByteArray auto &iv) : dec{key, iv} { }

    Vec<u8> Decrypt(const ByteArray auto &v) {
      return dec.Update(v);
    }

    ~AES128CTRDecryptor() = default;
  };

} // namespace crypto

#endif // ENCRYPTOR_HH
