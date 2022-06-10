#include "ServerHelloMessage.h"

size_t ServerHelloMessage::GetTotalSize() const {
  return SizeCalculator{}
      << sign_length
      << server_length
      << certificate_length

      << sign_server_client_random
      << server_dh_pubkey
      << certificate;
}

NetworkBuffer ServerHelloMessage::Serialize() const {
  return NetworkBuffer{}
      << rh
      << sign_length
      << server_length
      << certificate_length

      << sign_server_client_random
      << server_dh_pubkey
      << certificate;
}

Vec<u8> ServerHelloMessage::GetDataToSignWith(const Vec<u8> &client_dh_pub_key) const {
  return NetworkBuffer{}
      << client_dh_pub_key
      << server_dh_pubkey;
}

ServerHelloMessage ServerHelloMessage::From(const Vec<u8> &dh_public_key,
                                            const ClientHelloMessage &received_client_hello,
                                            const Vec<u8> &certificate,
                                            const SecVec<u8> &prv_key) {
  Vec<u8> pub_key = GetPublicKeyFromId(received_client_hello.client_id);
  if (!crypto::SignatureVerification::Make(pub_key,
                                           received_client_hello.GetDataToSign(),
                                           received_client_hello.sign)) {
    throw std::runtime_error{"Invalid signature"};
  }

  auto rv = ServerHelloMessage{};
  rv.server_dh_pubkey = dh_public_key;
  rv.server_length = rv.server_dh_pubkey.size();
  auto tmp = rv.GetDataToSignWith(received_client_hello.client_dh_pubkey);

  rv.sign_server_client_random = crypto::Signature::Make(prv_key, tmp);
  rv.sign_length = rv.sign_server_client_random.size();
  rv.certificate = certificate;
  rv.certificate_length = rv.certificate.size();

  rv.rh.length = rv.GetTotalSize();
  return rv;
}

std::shared_ptr<ServerHelloMessage>
ServerHelloMessage::Deserialize(const S3LHeader &rh, const Vec<u8> &content_bytes) {
  auto network_buffer = NetworkBuffer{content_bytes};
  auto rv = std::make_shared<ServerHelloMessage>(rh);
  network_buffer
      >> rv->sign_length
      >> rv->server_length
      >> rv->certificate_length;

  rv->sign_server_client_random = network_buffer.PopBytes(rv->sign_length);
  rv->server_dh_pubkey = network_buffer.PopBytes(rv->server_length);
  rv->certificate = network_buffer.PopBytes(rv->certificate_length);
  return rv;
}


void ServerHelloMessage::ValidateOrThrow(const Vec<u8> &client_dh_pubkey,
                                         const std::string &common_name,
                                         const std::string &root_ca_path) const {
  if (!crypto::CertificateIsValid(certificate, root_ca_path)) {
    throw std::runtime_error{"certificate is not valid"};
  }
  auto name = crypto::X509_mng{certificate}.GetName();
  if (name != common_name) {
    throw std::runtime_error{"certificate common name is not valid"};
  }
  Vec<u8> pub_key = crypto::ExtractPublicKey(certificate);
  if (!crypto::SignatureVerification::Make(pub_key,
                                           GetDataToSignWith(client_dh_pubkey),
                                           sign_server_client_random)) {
    throw std::runtime_error{"invalid server signature"};
  }

}

