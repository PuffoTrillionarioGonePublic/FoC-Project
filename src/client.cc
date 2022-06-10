#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
// TODO change this import
#include "ALP/object_io.h"
#include "S3L/IOChannel.h"
#include "S3L/SecureDataChannel.h"
#include "util.h"

struct ListParams {
  std::string path;
  DECL_FOR_SERIALIZATION(ListParams, path)
};

constexpr static char const* kCommands[] = {
    "upload", "download", "delete", "list", "rename", "logout", "help"};

constexpr static auto kCommandsNumber =
    sizeof(kCommands) / sizeof(kCommands[0]);

enum Command { kUpload, kDownload, kDelete, kList, kRename, kLogout, kHelp };

constexpr static std::tuple<Command, size_t> kCommandsArray[] = {
    {kUpload, 1}, {kDownload, 1}, {kDelete, 1}, {kList, 0},
    {kRename, 2}, {kLogout, 0},   {kHelp, 0}};

class ExitException : public std::exception {
  std::string msg_;

 public:
  explicit ExitException(std::string msg = "\nexiting...") {
    msg_ = std::move(msg);
  }

  [[nodiscard]] const char* what() const noexcept override {
    return msg_.c_str();
  }
};

auto CommandFromString(const std::string& s) -> std::tuple<Command, size_t> {
  for (size_t i = 0; i < kCommandsNumber; i++) {
    if (kCommands[i] == s) {
      return kCommandsArray[i];
    }
  }
  throw std::runtime_error{"invalid command"};
}

struct FileUploadParams {
  std::string path;
  DECL_FOR_SERIALIZATION(FileUploadParams, path)
};

const size_t kBufferSize = (1UL << 16);

void UploadHandler(IOChannel& io, const std::string& file) {
  auto is = std::ifstream{file, std::ios::binary | std::ios::ate};
  if (!is) {
    std::cerr << "File not found" << std::endl;
    return;
  }
  auto size = is.tellg();
  is.seekg(0);
  WriteObject(
      io,
      FileUploadParams{.path = std::filesystem::path{file}.filename().string()},
      "FileUpload");
  auto error = ReadObject<std::string>(io);
  if (!error.empty()) {
    std::cerr << error << std::endl;
    return;
  }
  size_t offset = 0;

  auto v = Vec<u8>(kBufferSize);
  do {
    auto n_bytes = std::min<size_t>(kBufferSize, size);
    v.resize(n_bytes);
    is.read((char*)v.data(), n_bytes);
    WriteFileChunk(io, v, offset, "UploadFileChunk",
                   std::filesystem::path{file}.filename().string());
    offset += n_bytes;
    size -= n_bytes;
  } while (size > 0);
};

struct DownloadParams {
  std::string path;
  DECL_FOR_SERIALIZATION(DownloadParams, path)
};

struct FileToDownloadInfo {
  size_t size;
  std::string nonce;
  std::string error_msg;
  DECL_FOR_SERIALIZATION(FileToDownloadInfo, size, nonce, error_msg)
};

void DownloadHandler(IOChannel& io, const std::string& file) {
  WriteObject(
      io,
      DownloadParams{.path = std::filesystem::path{file}.filename().string()},
      "FileDownload");
  auto file_info = ReadObject<FileToDownloadInfo>(io);

  if (!file_info.error_msg.empty()) {
    std::cerr << file_info.error_msg << std::endl;
    return;
  }
  auto ofs = std::ofstream{file, std::ios::binary | std::ios::ate};
  if (!ofs) {
    std::cerr << "can't download file" << std::endl;
    return;
  }

  size_t offset = 0;
  do {
    auto [chunk, offs] = ReadFileChunk(io);
    assert(offset == offs);
    ofs.seekp(offset, std::ios::beg);
    ofs.write((const char*)chunk.data(), chunk.size());
    offset += chunk.size();
  } while (offset < file_info.size);
}

struct DeleteFileRequest {
  std::string path;
  DECL_FOR_SERIALIZATION(DeleteFileRequest, path)
};

struct DeleteFileRequestRet {
  std::string nonce;
  std::string error_msg;
  DECL_FOR_SERIALIZATION(DeleteFileRequestRet, nonce, error_msg)
};

struct DeleteConfirm {
  std::string nonce;
  std::string res;
  DECL_FOR_SERIALIZATION(DeleteConfirm, nonce, res)
};

void DeleteHandler(IOChannel& io, const std::string& file) {
  WriteObject(io, DeleteFileRequest{.path = file}, "DeleteFileRequest");
  auto res = ReadObject<DeleteFileRequestRet>(io);
  if (!res.error_msg.empty()) {
    std::cerr << res.error_msg << std::endl;
    return;
  }
  std::string nonce = res.nonce;
  std::cout << "Do you confirm? [y/n]" << std::endl;
  auto confirm = std::string{};
  std::cout << ">>> ";
  std::cout.flush();
  std::getline(std::cin, confirm);
  if (!std::cin) {
    throw ExitException{};
  }
  if (confirm != "y") {
    confirm = "n";
  }
  auto delete_confirm = DeleteConfirm{.nonce = nonce, .res = confirm};
  WriteObject(io, delete_confirm, "DeleteFile");
  auto response = ReadObject<std::string>(io);
  std::cout << response << std::endl;
}

void ListHandler(IOChannel& io) {
  CallEndpoint(io, "ListFiles");
  auto rv = ReadObject<std::string>(io);
  std::cout << rv << std::endl;
}

struct RenameParams {
  std::string old_path;
  std::string new_path;
  DECL_FOR_SERIALIZATION(RenameParams, old_path, new_path)
};

void RenameHandler(IOChannel& io, const std::string& old_name,
                   const std::string& new_name) {
  WriteObject(io, RenameParams{.old_path = old_name, .new_path = new_name},
              "MoveFile");
  auto rv = ReadObject<std::string>(io);
  std::cout << rv << std::endl;
}

void LogoutHandler(IOChannel& io) { io.Close(); }

auto ReadCommand(const std::string& str)
    -> std::tuple<Command, std::vector<std::string>> {
  auto result = std::vector<std::string>{};
  boost::split(result, str, boost::is_any_of(" "));
  if (result.empty()) {
    throw std::runtime_error{"invalid command"};
  }
  auto [command, expected_argc] = CommandFromString(result[0]);
  if (result.size() - 1 != expected_argc) {
    throw std::runtime_error{"invalid number of arguments"};
  }
  return {command, {result.begin() + 1, result.end()}};
}

std::string ListCommands() {
  auto ss = std::stringstream{};
  for (const auto& scan : kCommands) {
    ss << scan << "  ";
  }
  return ss.str();
}

void Routine(IOChannel& io) {
  auto buf = std::string{};
  std::cout << ListCommands() << std::endl;
  for (;;) {
    try {
      std::cout << ">>> ";
      std::cout.flush();
      std::getline(std::cin, buf);
      if (!std::cin) {
        throw ExitException{};
      }
      auto [command, args] = ReadCommand(buf);
      switch (command) {
        case kUpload:
          UploadHandler(io, args.at(0));
          break;
        case kDownload:
          DownloadHandler(io, args.at(0));
          break;
        case kDelete:
          DeleteHandler(io, args.at(0));
          break;
        case kList:
          ListHandler(io);
          break;
        case kRename:
          RenameHandler(io, args.at(0), args.at(1));
          break;
        case kHelp:
          std::cout << ListCommands() << std::endl;
          break;
        case kLogout:
          throw ExitException{"exiting..."};
      }
    } catch (ExitException& ex) {
      std::cout << ex.what() << std::endl;
      return;
    } catch (std::exception& ex) {
      std::cerr << ex.what() << std::endl;
    }
  }
}

int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;
  using namespace boost::asio::ip;
  
  // silence logs
  std::ofstream nullstream;
  std::clog.rdbuf(nullstream.rdbuf());

  try {
    auto tree = boost::property_tree::ptree{};
    boost::property_tree::read_xml("../data/client-config.xml", tree);
    auto prv_key_path = tree.get<std::string>("config.private-key-path");
    auto id = tree.get<u64>("config.id");
    auto server_ip = tree.get<std::string>("config.server-ip");
    auto port = tree.get<u16>("config.port");
    auto server_common_name =
        tree.get<std::string>("config.server-common-name");
    auto root_ca_path = tree.get<std::string>("config.root-ca-path");
    auto address =
        tcp::endpoint{boost::asio::ip::make_address(server_ip), port};
    auto io_service = std::make_shared<boost::asio::io_service>();
    auto tcp_socket = std::make_shared<tcp::socket>(*io_service);
    tcp_socket->connect(address);
    auto socket_io = std::make_shared<SocketChannel>(io_service, tcp_socket);
    SecVec<u8> prv_key = crypto::PrivkeyFromFileAsBytes(prv_key_path);
    auto io = SecureDataChannel::ConnectToDataChannelAsClient(
        socket_io, prv_key, id, server_common_name, root_ca_path);
    Routine(*io);
  } catch (std::exception& ex) {
    std::cerr << ex.what() << std::endl;
  }
}
