#ifndef S3L_APPLICATIONLAYER_CLIENTINFO_H_
#define S3L_APPLICATIONLAYER_CLIENTINFO_H_

#include <string>
#include <filesystem>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <optional>
#include "util.h"
#include "Crypto/api.hh"

struct ClientInfo final {
  std::filesystem::path base_path{};
  std::string username{};
  u64 id{};
  std::string public_key_path{};
  
  std::optional<std::string> deletion_nonce{};
  std::optional<std::string> target_path{};

  std::optional<std::string> file_nonce{};
  std::optional<std::string> file_path{};

  std::optional<std::string> file_download_nonce{};
  std::optional<std::string> file_download_path{};


  ClientInfo() = default;

  static ClientInfo FromClientId(u64 client_id) {
    return ClientInfo(client_id);
  }

private:
  explicit ClientInfo(u64 client_id);

};

#endif //S3L_APPLICATIONLAYER_CLIENTINFO_H_
