#ifndef ALPHEADER
#define ALPHEADER

#include <boost/serialization/serialization.hpp>
#include <string>
#include <boost/serialization/nvp.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/optional.hpp>
#include "xml.h"
#include "util.h"

template<typename T>
using Option = boost::optional<T>;

struct ALPHeader {
  u16 reply{};
  std::string content_type{};
  std::string endpoint{};
  std::string method{};
  size_t body_size;
  Option<size_t> range_begin{boost::none};
  Option<std::string> file_path{boost::none};

  DECL_FOR_SERIALIZATION(ALPHeader,
      reply,
      content_type,
      endpoint,
      method,
      body_size,
      range_begin,
      file_path
  )

};



BOOST_CLASS_IMPLEMENTATION(ALPHeader, object_serializable)

#endif //BOOSTSYNCHRONOUSSERVER_ALPHEADER_H
