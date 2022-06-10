#ifndef MACRO_CONTROLLER_UTIL_H
#define MACRO_CONTROLLER_UTIL_H

#include <boost/algorithm/string.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/asio.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/mp11/algorithm.hpp>
#include <boost/optional.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/seq.hpp>
#include <boost/preprocessor/seq/fold_left.hpp>
#include <boost/preprocessor/variadic.hpp>
#include <boost/preprocessor/variadic/to_seq.hpp>
#include <boost/serialization/level.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>
#include <tuple>
#include <variant>
#include "ALPHeader.h"
#include "ClientInfo.h"
#include "S3L/SecureDataChannel.h"
#include "object_io.h"
#include "util.h"
#include "xml.h"


template<typename T>
struct tag {
  using type = T;
};

namespace List {
namespace impl {
template<typename Name, std::size_t Index>
struct ElemReader {
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-template-friend"
#endif

  friend constexpr auto adl_ImpListElem(ElemReader<Name, Index>);

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
};

template<typename Name, std::size_t Index, typename Value>
struct ElemWriter {
  friend constexpr auto adl_ImpListElem(ElemReader<Name, Index>) {
    return tag<Value>{};
  }
};

constexpr void adl_ImpListElem() {} // A dummy ADL target.

template<typename Name, std::size_t Index, typename Unique, typename = void>
struct CalcSize : std::integral_constant<std::size_t, Index> {
};

template<typename Name, std::size_t Index, typename Unique>
struct CalcSize<Name, Index, Unique, decltype(void(adl_ImpListElem(ElemReader<Name, Index>{})))>
    : CalcSize<Name, Index + 1, Unique> {
};

template<typename Name, std::size_t Index, typename Unique>
using ReadElem = typename decltype(adl_ImpListElem(ElemReader<Name, Index>{}))::type;

template<template<typename...> typename List, typename Name, typename I, typename Unique>
struct ReadElemList {
};
template<template<typename...> typename List, typename Name, std::size_t ...I, typename Unique>
struct ReadElemList<List, Name, std::index_sequence<I...>, Unique> {
  using type = List<ReadElem<Name, I, Unique>...>;
};
}

struct DefaultUnique {
};

// Calculates the current list size.
template<typename Name, typename Unique = DefaultUnique>
inline constexpr std::size_t size = impl::CalcSize<Name, 0, Unique>::value;

// Touch this type to append `Value` to the list.
template<typename Name, typename Value, typename Unique = Value>
using PushBack = impl::ElemWriter<Name, size<Name, Unique>, Value>;

// Returns the type previously passed to `WriteState`, or causes a SFINAE error.
template<typename Name, std::size_t I, typename Unique = DefaultUnique>
using Elem = impl::ReadElem<Name, I, Unique>;

template<template<typename...> typename List, typename Name, typename Unique = DefaultUnique>
using Elems = typename impl::ReadElemList<List,
                                          Name,
                                          std::make_index_sequence<size<Name, Unique>>,
                                          Unique>::type;
}

struct Dummy {
  template<typename T>
  Dummy(const T &) {}
};

using namespace boost::asio::ip;

class FileEndpointParams {
 public:
  std::filesystem::path path;
  size_t offset;
  Vec<u8> body;

  void callback(auto self, auto g) {}
};

#define FILE_ENDPOINT(method_name) \
    struct method_name##Params : public FileEndpointParams {   \
        friend class AbstractController;    \
        int dummy;  \
        FileEndpointParams fep; \
        void callback(auto self, auto g) {method_name(self, g);};   \
        static constexpr auto METHOD_NAME = #method_name; \
        DECL_FOR_SERIALIZATION(method_name##Params, dummy)  \
    }; \
    static void method_name(auto self, auto p) {    \
        self->method_name(p);   \
    }   \
    Dummy MAKE_UNIQUE_VARIABLE_NAME(a)= List::PushBack<TypesArray, method_name##Params>{};

//#define DEPAREN(X) ESC(ISH X)
//#define ISH(...) ISH __VA_ARGS__
//#define ESC(...) ESC_(__VA_ARGS__)
//#define ESC_(...) VAN ## __VA_ARGS__
//#define VANISH

#define XML_ENDPOINT(typed_params, params, method_name) \
        struct method_name##Params {    \
            friend class AbstractController;    \
            void callback(auto self, auto g) {method_name(self, g);}   \
        public: \
            typed_params;   \
            static constexpr auto METHOD_NAME = #method_name;   \
            DECL_FOR_SERIALIZATION(method_name##Params, DEPAREN(params))    \
        };  \
        static void method_name(auto self, auto p) {    \
            self->method_name(p);   \
        }   \
        Dummy MAKE_UNIQUE_VARIABLE_NAME(a) = List::PushBack<TypesArray, method_name##Params>{};

#define XML_ENDPOINT_NO_ARGS(method_name) XML_ENDPOINT(u8 dummy, (dummy), method_name)

template<typename SubClass>
struct AbstractController {
  std::shared_ptr<IOChannel> io_;
  struct TypesArray {
  };

  using BufferType = std::variant<std::string, Vec<u8>>;

  ALPHeader GetHeader() {
    Vec<u8> v = io_->Read(HEADER_SIZE);
    auto header_xml = std::string{v.begin(), v.end()};
    while (header_xml[header_xml.size() - 1] == ' ') {
      header_xml.resize(header_xml.size() - 1);
    }
    auto header = xml::Deserialize<ALPHeader>(header_xml);
    return header;
  }

  template<typename T>
  T GetBody(const ALPHeader &header) {
    auto v = io_->Read(header.body_size);
    auto body = T{v.begin(), v.end()};
    return body;
  }

  std::tuple<ALPHeader, BufferType> ReadParams() {
    using namespace boost::mp11;
    ALPHeader header = GetHeader();
    if (header.content_type == "text/xml") {
      auto body = GetBody<std::string>(header);
      return {header, body};
    } else if (header.content_type == "binary/file_chunk") {
      auto body = GetBody<Vec<u8>>(header);
      return {header, body};
    }

    throw std::runtime_error{"bad packet"};

  };

  template<typename Tuple>
  static bool GenericInvokeCallback(void *self,
                                    const ALPHeader &header,
                                    const BufferType &body) {
    using namespace boost::mp11;
    const size_t N = std::tuple_size_v<Tuple>;
    bool ok = false;
    try {
      mp_for_each<mp_iota_c<N>>([&](auto I) {
        try {
          using CurrentType = typename std::tuple_element<I, Tuple>::type;
          if (CurrentType::METHOD_NAME == header.endpoint) {
            if (header.content_type == "text/xml") {
              auto elem = xml::Deserialize<CurrentType>(std::get<std::string>(body));
              elem.callback((SubClass *) self, elem);
            } else if (header.content_type == "binary/file_chunk") {
              auto path = std::filesystem::path{header.file_path.value()};
              if constexpr(std::is_base_of<FileEndpointParams, CurrentType>::value) {
                CurrentType c{};
                c.path = path;
                c.offset = header.range_begin.value();
                c.body = std::get<Vec<u8>>(body);
                c.callback((SubClass *) self, c);
              }

            }
            ok = true;
          }
        } catch (std::exception &ex) {
          std::clog << ex.what() << std::endl;
        }
      });
    } catch (...) {}
    return ok;
  }

  template<typename T>
  static auto GetInvokeCallback(const auto &invoke_function) -> std::function<bool(void *,
                                                                                   const ALPHeader &,
                                                                                   const BufferType &)> {
    return [&](void *self, const ALPHeader &a, const BufferType &b) -> bool {
      return invoke_function.template operator()<T>(self, a, b);
    };
  }

  std::function<bool(void *, const ALPHeader &, const BufferType &)> InvokeCallback;
  ClientInfo client_info_{};

 protected:

  ClientInfo &GetClientInfo() {
    return client_info_;
  }

 public:

  explicit AbstractController(std::shared_ptr<IOChannel> io, u64 client_id) {
    io_ = std::move(io);
    client_info_ = ClientInfo::FromClientId(client_id);

    std::clog << "User " << client_info_.username << " with id " << client_info_.id << " connected"
              << std::endl;
    auto generic_invoke_callback_fn = []<typename T>(void *self,
                                                     const ALPHeader &header,
                                                     const BufferType &body) -> bool {
      return GenericInvokeCallback<T>(self, header, body);
    };
    using TypesArrayWithCallback = List::Elems<std::tuple, TypesArray, decltype([] {})>;
    InvokeCallback =
        GetInvokeCallback<TypesArrayWithCallback>(generic_invoke_callback_fn);
  }

  void WriteObject(auto obj) {
    if constexpr (std::is_same_v<decltype(obj), const char *>) {
      ::WriteObject(*io_, std::string{obj});
    } else {
      ::WriteObject(*io_, obj);
    }

  }

  void WriteFileChunk(const Vec<u8> &v, size_t offset, const std::string &file_name) {
    ::WriteFileChunk(*io_, v, offset, "", file_name);
  }

  void Start() {
    try {
      while (!io_->IsClosed()) {
        auto [header, body] = ReadParams();
        InvokeCallback(this, header, body);
      }
    } catch (std::exception &ex) {
      std::clog << ex.what() << std::endl;
    }
  }

};

#endif //MACRO_CONTROLLER_UTIL_H
