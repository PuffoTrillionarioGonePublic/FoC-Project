#ifndef SECURE_COMMUNICATION_UTILITY_H
#define SECURE_COMMUNICATION_UTILITY_H

#include "../Crypto/api.hh"
#include "../util.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <memory>
#include <stdexcept>

inline Vec<u8> GetPublicKeyFromId(u64 id) {
  auto tree = boost::property_tree::ptree{};

  boost::property_tree::read_xml("../data/users.xml", tree);
  for (boost::property_tree::ptree::value_type &v : tree.get_child("users")) {
    auto &value = v.second;
    if (value.get<u64>("id") == id) {
      return crypto::PubkeyFromFileAsBytes(
          value.get<std::string>("public-key-path"));
    }
  }
  throw std::runtime_error{"error"};
}

template <typename>
struct IsStdSharedPtr : std::false_type {};

template <typename T>
struct IsStdSharedPtr<std::shared_ptr<T>> : std::true_type {};

template <typename T>
inline bool InstanceOf(const auto &obj) {
  if constexpr (IsStdSharedPtr<std::decay_t<decltype(obj)>>::value) {
    return std::dynamic_pointer_cast<T>(obj) != nullptr;
  } else {
    return dynamic_cast<const T *>(&obj) != nullptr;
  }
}

template<std::integral T, size_t N>
constexpr inline bool operator==(const std::array<T, N>&, const std::array<T, N>&) {
  static_assert(sizeof(T) == 0);
  throw std::runtime_error{"this line should't be executed and this function is not valid"};
  return false;
}


#endif