#include "ClientInfo.h"

ClientInfo::ClientInfo(u64 client_id) {
  auto tree = boost::property_tree::ptree{};
  boost::property_tree::read_xml("../data/users.xml", tree);
  for (boost::property_tree::ptree::value_type &v : tree.get_child("users")) {
    auto &value = v.second;
    if (value.get<u64>("id") == client_id) {
      base_path = value.get<std::string>("base-path");
      username = value.get<std::string>("name");
      id = value.get<u64>("id");
      public_key_path = value.get<std::string>("public-key-path");
      return;
    }
  }
  throw std::runtime_error{"user not found"};
}
