#ifndef XML_H
#define XML_H
#include <boost/archive/xml_iarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>
#include <boost/preprocessor/seq/fold_left.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/serialization/vector.hpp>
#include <string>
#include <variant>

#define CONCAT_(prefix, suffix) prefix##suffix
#define CONCAT(prefix, suffix) CONCAT_(prefix, suffix)
#define MAKE_UNIQUE_VARIABLE_NAME(prefix) CONCAT(prefix##_, __COUNTER__)

#define OP(s, state, x) state &BOOST_SERIALIZATION_NVP(x)
#define UTIL_FUNC_FOR_SERIALIZATION(archive, ...) \
  BOOST_PP_SEQ_FOLD_LEFT(OP, archive, BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))
#define DECL_FOR_SERIALIZATION(class_name, ...)     \
  void serialize(auto &__ar, unsigned) {            \
    UTIL_FUNC_FOR_SERIALIZATION(__ar, __VA_ARGS__); \
  }                                                 \
  constexpr static auto CLASS_NAME = #class_name;   \
  friend class boost::serialization::access;

#define DEPAREN(X) ESC(ISH X)
#define ISH(...) ISH __VA_ARGS__
#define ESC(...) ESC_(__VA_ARGS__)
#define ESC_(...) VAN##__VA_ARGS__
#define VANISH
struct AnonXmlStruct {};

namespace xml {

template <typename T>
inline std::string Serialize(const T &obj) {
  std::ostringstream ss{};
  boost::archive::xml_oarchive archive(ss, boost::archive::no_header);
  if constexpr (std::is_base_of_v<AnonXmlStruct, T>) {
    archive << boost::serialization::make_nvp("__AnonStruct__", obj);
  } else if constexpr (std::is_same_v<T, std::string>) {
    archive << boost::serialization::make_nvp("string", obj);
  } else {
    archive << boost::serialization::make_nvp(T::CLASS_NAME, obj);
  }
  return ss.str();
}

template <typename T>
inline T Deserialize(const std::string &s) {
  std::istringstream ss{s};
  boost::archive::xml_iarchive archive(ss, boost::archive::no_header);
  T obj{};
  archive >> BOOST_SERIALIZATION_NVP(obj);
  return obj;
}

template <typename T>
inline T Deserialize(const std::vector<uint8_t> &v) {
  auto s = std::string{v.begin(), v.end()};
  return Deserialize<T>(s);
}
}  // namespace xml

#define XML_SER(typed_fields, fields)                                      \
  ({                                                                       \
    struct CONCAT(__AnonStruct, __COUNTER__) : public AnonXmlStruct {      \
      DEPAREN(typed_fields);                                               \
      void serialize(                                                      \
          const std::variant<                                              \
              std::reference_wrapper<boost::archive::xml_oarchive>,        \
              std::reference_wrapper<boost::archive::xml_iarchive>> &__ar, \
          unsigned) {                                                      \
        std::remove_const_t<decltype(__ar)> &__ar__ =                      \
            const_cast<std::remove_const_t<decltype(__ar) &>>(__ar);       \
        if (auto pval = std::get_if<                                       \
                std::reference_wrapper<boost::archive::xml_oarchive>>(     \
                &__ar__))                                                  \
          UTIL_FUNC_FOR_SERIALIZATION(std::get<0>(__ar__).get(),           \
                                      DEPAREN(fields));                    \
        else                                                               \
          UTIL_FUNC_FOR_SERIALIZATION(std::get<1>(__ar__).get(),           \
                                      DEPAREN(fields));                    \
      }                                                                    \
      friend class boost::serialization::access;                           \
    } __obj__;                                                             \
    xml::Serialize(__obj__);                                               \
  })

#endif  // XML_H
