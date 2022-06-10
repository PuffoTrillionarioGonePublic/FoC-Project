#include "crypto.hh"
#include <stdio.h>

template<ByteArray T>
void puthex(T &t) {
  for (const auto &e : t)
    printf("%02x", e);
  printf("\n");
}

template<typename T>
void putchars(const std::vector<T> &t) {
  for (const auto &e : t)
    putc(e, stdout);
  putc('\n', stdout);
}
void testRandomBytes() {
  auto r = crypto::RandomBytes(16);
  puthex(r);
}

void testHash() {
  auto s = "Hello world!"_u8;
  // auto h = crypto::SHA256().Update((const u8*)s.data(), s.size()).Digest();
  auto h = crypto::SHA256::Make(s);

  /*py
  >>> import hashlib
  >>> hashlib.sha256(b"Hello world!").hexdigest()
  'c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a'
  */
  puthex(h);
}

void testHmac() {
  auto s = "Hello world!"_u8;
  auto k = std::vector<u8>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  auto hmac = crypto::HMAC::Make(k, s);

  /*py
  >>> import hmac
  >>> import hashlib
  >>> hmac.new(bytes(range(16)), b"Hello world!", hashlib.sha256).hexdigest()
  '5f382b71a08a0aa4de771848558ffb540c4115ed5ec53be70ae27f127ec0a4d4'
  */
  puthex(hmac);
}

void testctr() {
  auto p = "Hello world!"_u8;
  auto k = SecVec<u8>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  auto iv = Vec<u8>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  auto c = crypto::AESEncrypt128CTR::Make(p, k, iv);

  /*
  >>> from Crypto.Cipher import AES
  >>> from Crypto.Util import Counter
  >>> c = Counter.new(16*8, initial_value=int.from_bytes(bytes(range(16)), "big"))
  >>> AES.new(bytes(range(16)), AES.MODE_CTR, counter=c).encrypt(b"Hello world!").hex()
  '42f167d92e4e872a83aff079'
  */
  puthex(c);

  auto pp = crypto::AESDecrypt128CTR::Make(c, k, iv);

  auto s = std::string(pp.begin(), pp.end());
  printf("%s\n", s.c_str());
}
/*
void testPubkey() {
  auto pubkey = crypto::PubkeyFromFile("../keys/mykey.pub");
  auto privkey = crypto::PrivkeyFromFile("../keys/mykey.pem");

  auto msg = crypto::RandomBytes(32);
  auto enc = crypto::PKEYEncrypt::Make(pubkey, msg);

  puthex(enc);

  auto m = crypto::PKEYDecrypt::Make(privkey, enc);

  puthex(m);

  auto r = memcmp(msg.data(), m.data(), m.size());
  printf("%s\n", !r ? "true" : "false");

  EVP_PKEY_free(pubkey);
  EVP_PKEY_free(privkey);
}

void testSign() {
  auto pubkey = crypto::PubkeyFromFile("../keys/mykey.pub");
  auto privkey = crypto::PrivkeyFromFile("../keys/mykey.pem");

  auto msg = "Hello world!"_u8;
  auto sign = crypto::Signature::Make(privkey, msg);

  puthex(sign);

  auto r = crypto::SignatureVerification::Make(pubkey, msg, sign);

  printf("%s\n", r ? "true" : "false");

  EVP_PKEY_free(pubkey);
  EVP_PKEY_free(privkey);
}

void testcert() {
  auto rootcert = crypto::X509_mng("../keys/rootca.com.crt");

  auto cert = crypto::X509_mng("../keys/s3.puffotrillionario.com.crt");

  auto store = crypto::X509_Store_mng();
  store.AddCert(rootcert);

  auto r = store.VerifyCert(cert);
  printf("%s\n", r ? "true" : "false");

  putchars(rootcert.ToBytes()); // ok
  putchars(cert.ToBytes()); // ok
}
*/
void testdh() {
  auto dh_a = crypto::DH_mng();
  auto A = dh_a.GetPubkeyAsBytes();
  std::clog << A << std::endl;
  auto dh_b = crypto::DH_mng();
  auto B = dh_b.GetPubkeyAsBytes();
  std::clog << B << std::endl;

  auto skeya = dh_a.GetSharedKey(B);
  auto skeyb = dh_b.GetSharedKey(A);

  puthex(skeya);
  puthex(skeyb);
}

int main() {
  //testRandomBytes();
  //testHash();
  //testHmac();
  //testctr();
  //testPubkey();
  //testSign();
  //testcert();
  testdh();
}