#include "ServerHelloMessage.h"

size_t ServerHelloMessage::GetTotalSize() const {
  return SizeCalculator{} << signature_length << server_dh_pubkey_length << certificate_length

                          << signature << server_dh_pubkey
                          << certificate;
}

NetworkBuffer ServerHelloMessage::Serialize() const {
  return NetworkBuffer{} << header << signature_length << server_dh_pubkey_length
                         << certificate_length

                         << signature << server_dh_pubkey
                         << certificate;
}

// TODO: change this
Vec<u8> ServerHelloMessage::GetDataToSignWith(
    const Vec<u8> &client_dh_pub_key) const {
  return NetworkBuffer{} << server_dh_pubkey << client_dh_pub_key;
}

ServerHelloMessage ServerHelloMessage::From(
    const Vec<u8> &server_dh_public_key,
    const Vec<u8> &client_dh_pubkey,
    const Vec<u8> &certificate,
    const SecVec<u8> &prv_key) {
  auto rv = ServerHelloMessage{};
  rv.server_dh_pubkey = server_dh_public_key;
  rv.server_dh_pubkey_length = rv.server_dh_pubkey.size();
  auto tmp = rv.GetDataToSignWith(client_dh_pubkey);
  rv.signature = crypto::Signature::Make(prv_key, tmp);
  rv.signature_length = rv.signature.size();
  rv.certificate = certificate;
  rv.certificate_length = rv.certificate.size();
  rv.header.length = rv.GetTotalSize();
  return rv;
}

std::shared_ptr<ServerHelloMessage> ServerHelloMessage::Deserialize(
    const S3LHeader &rh, const Vec<u8> &content_bytes) {
  return std::make_shared<ServerHelloMessage>(rh, content_bytes);
}

void ServerHelloMessage::ValidateOrThrow(
    const Vec<u8> &client_dh_pubkey, const std::string &common_name,
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
                                           signature)) {
    throw std::runtime_error{"invalid server signature"};
  }
}
ServerHelloMessage::ServerHelloMessage(const S3LHeader &h, const Vec<u8> &content_bytes) {
  auto network_buffer = NetworkBuffer{} << content_bytes;
  header = h;
  network_buffer >> signature_length >> server_dh_pubkey_length >> certificate_length;

  signature = network_buffer.PopBytes(signature_length);
  server_dh_pubkey = network_buffer.PopBytes(server_dh_pubkey_length);
  certificate = network_buffer.PopBytes(certificate_length);
}
