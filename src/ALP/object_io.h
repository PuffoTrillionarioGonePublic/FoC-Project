#ifndef BOOSTSYNCHRONOUSSERVER_UTIL_H
#define BOOSTSYNCHRONOUSSERVER_UTIL_H

#include "ALPHeader.h"
#include "../S3L/IOChannel.h"
#include "../S3L/SocketChannel.h"
#include "../util.h"
#include "xml.h"
#include <boost/algorithm/string.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/asio.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <any>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>
#include <utility>

static const int HEADER_SIZE = 1024;

struct DummyStruct {
  u8 dummy{};
  DummyStruct() = default;
  DECL_FOR_SERIALIZATION(DummyStruct, dummy)
};

inline void WriteObject(IOChannel &io, const auto &obj,
                        const std::string &endpoint = "") {
  ALPHeader alp_header{};
  std::string obj_serialized;
  try {
    obj_serialized = xml::Serialize(obj);
    alp_header.reply = 200;
    alp_header.endpoint = endpoint;
    alp_header.content_type = "text/xml";
    alp_header.body_size = obj_serialized.size();
  } catch (std::exception &ex) {
    alp_header.reply = 404;
  }
  std::string s = xml::Serialize(alp_header);
  while (s.size() < HEADER_SIZE) {
    s.push_back('\0');
  }
  io.Write(Vec<u8>(s.begin(), s.end()));
  io.Write(Vec<u8>(obj_serialized.begin(), obj_serialized.end()));
}

void CallEndpoint(IOChannel &io, const std::string &endpoint) {
  WriteObject(io, DummyStruct{}, endpoint);
}

void WriteFileChunk(IOChannel &io, const Vec<u8> &v, size_t offset,
                    const std::string &endpoint,
                    const std::string &file_path = "") {
  ALPHeader alp_header{};
  try {
    alp_header.reply = 200;
    alp_header.content_type = "binary/file_chunk";
    alp_header.endpoint = endpoint;
    alp_header.file_path = boost::make_optional(file_path);
    alp_header.body_size = v.size();
    alp_header.range_begin = boost::make_optional(offset);
  } catch (std::exception &ex) {
    alp_header.reply = 404;
  }
  std::string s = xml::Serialize(alp_header);
  while (s.size() < HEADER_SIZE) {
    s.push_back('\0');
  }
  io.Write(Vec<u8>(s.begin(), s.end()));
  io.Write(v);
}

auto ReadFileChunk(IOChannel &io) -> std::tuple<Vec<u8>, u64> {
  Vec<u8> buf = io.Read(HEADER_SIZE);
  auto header_xml = std::string{buf.begin(), buf.end()};
  header_xml.resize(strnlen(header_xml.c_str(), HEADER_SIZE));
  auto header = xml::Deserialize<ALPHeader>(header_xml);
  return {io.Read(header.body_size), *header.range_begin};
}

template <typename T>
T ReadObject(IOChannel &io) {
  Vec<u8> buf = io.Read(HEADER_SIZE);
  auto header_xml = std::string{buf.begin(), buf.end()};
  header_xml.resize(strnlen(header_xml.c_str(), HEADER_SIZE));
  auto header = xml::Deserialize<ALPHeader>(header_xml);
  buf = io.Read(header.body_size);
  auto body_xml = std::string{buf.begin(), buf.end()};
  return xml::Deserialize<T>(body_xml);
}

#endif  // BOOSTSYNCHRONOUSSERVER_UTIL_H
