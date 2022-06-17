#include "ALP/AbstractController.h"
#include "ALP/object_io.h"
#include "ALP/xml.h"
#include "S3L/IOChannel.h"
#include "S3L/SocketChannel.h"
#include "util.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <memory>
#include <regex>

bool ValidPath(const std::string &path) {
  const auto re = std::regex{R"(^\w[\w\.\-\+_]{0,19}$)"};
  return std::regex_match(path, re);
}

std::string GenerateRandomString(size_t n) {
  Vec<u8> bytes = crypto::RandomBytes(n);
  auto ss = std::stringstream{};
  for (u8 scan : bytes) {
    ss << (int)scan;
  }
  return ss.str();
}

static constexpr size_t KiB = 1024;
static constexpr size_t MiB = 1024 * KiB;
static constexpr size_t GiB = 1024 * MiB;

struct Controller : public AbstractController<Controller> {
  static constexpr size_t kMaxFileSize = 4 * GiB;

  explicit Controller(std::shared_ptr<IOChannel> io, u64 client_id)
      : AbstractController(std::move(io), client_id) {}

  XML_ENDPOINT(std::string path, (path), FileUpload)
  void FileUpload(auto p) {
    if (!ValidPath(p.path)) {
      WriteObject("path not valid");
      return;
    }
    auto path = GetClientInfo().base_path / p.path;
    auto ofs = std::ofstream{path};
    ofs.close();
    std::filesystem::resize_file(path, 0);
    // GetClientInfo().file_nonce = GenerateRandomString(32);
    // GetClientInfo().file_path = path;
    WriteObject("");
  }

  FILE_ENDPOINT(UploadFileChunk)
  void UploadFileChunk(const FileEndpointParams &p) {
    if (p.offset >= kMaxFileSize) {
      return;
    }
    if (!ValidPath(p.path.string())) {
      return;
    }
    auto path = GetClientInfo().base_path / p.path.filename().string();
    auto flags = std::ios::binary | std::ios::out | std::ios::in;
    auto ofs = std::ofstream(path, flags);
    ofs.seekp(p.offset, std::ios::beg);
    ofs.write((const char *)p.body.data(), p.body.size());
    ofs.flush();
  }

  struct FileToDownloadInfo {
    size_t size;
    std::string nonce;
    std::string error_msg;
    DECL_FOR_SERIALIZATION(FileToDownloadInfo, size, nonce, error_msg)
  };

  XML_ENDPOINT(std::string path, (path), FileDownload)

  void FileDownload(auto p) {
    if (!ValidPath(p.path)) {
      WriteObject(FileToDownloadInfo{
          .size = 0, .nonce = "", .error_msg = "invalid path"});
      return;
    }
    auto path = GetClientInfo().base_path / p.path;
    auto ifs = std::ifstream{path};
    if (!ifs) {
      WriteObject(FileToDownloadInfo{
          .size = 0, .nonce = "", .error_msg = "file not found"});
      return;
    }
    GetClientInfo().file_download_nonce = GenerateRandomString(32);
    GetClientInfo().file_download_path = path;
    WriteObject(
        FileToDownloadInfo{.size = std::filesystem::file_size(path),
                           .nonce = *GetClientInfo().file_download_nonce,
                           .error_msg = ""});

    auto file_size = std::filesystem::file_size(path);
    size_t rem;
    size_t offset = 0;
    while ((rem = file_size - offset) > 0) {
      auto chunk_size = std::min<size_t>(rem, 4096);
      auto v = Vec<u8>(chunk_size);
      ifs.read((char *)&v[0], chunk_size);
      WriteFileChunk(v, offset,
                     std::filesystem::path{path}.filename().string());
      offset += chunk_size;
    }
  }

  /**
   *
   * The client asks to the server the list of the filenames of the available
   * files in his dedicated storage. The client prints to screen the list.
   */

  XML_ENDPOINT_NO_ARGS(ListFiles)

  void ListFiles(auto) {
    auto path = GetClientInfo().base_path;
    std::stringstream ss;
    for (const auto &entry : std::filesystem::directory_iterator(path)) {
      ss << entry.path().filename().string() << "  ";
    }
    auto str = ss.str();
    while (str.ends_with(' ')) {
      str.resize(str.size() - 1);
    }
    WriteObject(str);
  }

  /**
   * Specifies a file on the server machine.
   * Within the request, the clients sends the new filename.
   * If the renaming operation is not possible, the filename is not changed.
   */

  XML_ENDPOINT(std::string old_path;
               std::string new_path, (old_path, new_path), MoveFile)

  void MoveFile(auto p) {
    if (!ValidPath(p.old_path) || !ValidPath(p.new_path)) {
      WriteObject("invalid path");
      return;
    }
    try {
      auto old_path = GetClientInfo().base_path / p.old_path;
      auto new_path = GetClientInfo().base_path / p.new_path;
      // if (std::filesystem::exists(old_path)) {
      std::filesystem::rename(old_path, new_path);
      WriteObject("file renamed");
    } catch (...) {
      WriteObject("can't rename file");
      throw;
    }
  }

  /**
   * Delete: Specifies a file on the server machine.
   * The server asks the user for confirmation.
   * If the user confirms, the file is deleted from the server.
   */

  struct DeleteFileRequestRet {
    std::string nonce;
    std::string error_msg;
    DECL_FOR_SERIALIZATION(DeleteFileRequestRet, nonce, error_msg)
  };

  XML_ENDPOINT(std::string path, (path), DeleteFileRequest)

  void DeleteFileRequest(auto p) {
    if (!ValidPath(p.path)) {
      WriteObject(
          DeleteFileRequestRet{.nonce = "", .error_msg = "path not valid"});
      return;
    }
    GetClientInfo().deletion_nonce = GenerateRandomString(32);
    GetClientInfo().target_path = GetClientInfo().base_path / p.path;
    WriteObject(DeleteFileRequestRet{.nonce = *GetClientInfo().deletion_nonce,
                                     .error_msg = ""});
  }

  XML_ENDPOINT(std::string nonce; std::string res, (nonce, res), DeleteFile)

  void DeleteFile(auto p) {
    if (p.res == "y") {
      if (!GetClientInfo().deletion_nonce || !GetClientInfo().target_path ||
          p.nonce != *GetClientInfo().deletion_nonce) {
        WriteObject("can't delete file");
      } else {
        auto path = *GetClientInfo().target_path;
        std::filesystem::remove(path);
        GetClientInfo().deletion_nonce = {};
        GetClientInfo().target_path = {};
        WriteObject("file deleted");
      }
    } else if (p.res == "n") {
      WriteObject("");
    } else {
      WriteObject("");
    }
  }
};

struct Server {
  std::shared_ptr<boost::asio::io_service> io_service_;
  tcp::endpoint tcp_endpoint_;
  tcp::acceptor tcp_acceptor_;

 public:
  explicit Server(u16 port)
      : io_service_{std::make_shared<boost::asio::io_service>()},
        tcp_endpoint_{tcp::v4(), port},
        tcp_acceptor_{*io_service_, tcp_endpoint_} {}

  void Start(const SecVec<u8> &prv_key, const Vec<u8> &certificate) {
    for (;;) {
      auto executor = tcp_acceptor_.get_executor();
      auto &context = (boost::asio::io_service &)executor.context();
      auto shared_socket = std::make_shared<tcp::socket>(context);
      tcp_acceptor_.accept(*shared_socket);

      auto th = std::jthread{[this, certificate, prv_key, shared_socket] {
        try {
          auto socket_channel =
              std::make_shared<SocketChannel>(io_service_, shared_socket);

          auto [io, client_id] =
              SecureDataChannel::ConnectToDataChannelAsServer(
                  socket_channel, prv_key, certificate);
          Controller c{io, client_id};
          c.Start();
        } catch (std::exception &ex) {
          std::clog << ex.what() << std::endl;
        }
      }};
      th.detach();
    }
  }
};

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  // silence logs
  std::ofstream nullstream{};
  std::clog.rdbuf(nullstream.rdbuf());

  auto tree = boost::property_tree::ptree{};
  boost::property_tree::read_xml("../data/server-config.xml", tree);
  auto prv_key_path = tree.get<std::string>("config.private-key-path");
  auto certificate_path = tree.get<std::string>("config.certificate-path");
  SecVec<u8> prv_key = crypto::PrivkeyFromFileAsBytes(prv_key_path);
  Vec<u8> certificate = crypto::ReadCertificate(certificate_path);
  auto server = std::make_shared<Server>(9000);
  auto server_thread = std::jthread{
      [server, prv_key, certificate] { server->Start(prv_key, certificate); }};

  server_thread.join();
  return 0;
}