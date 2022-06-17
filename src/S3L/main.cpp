
#include "../util.h"
#include <iostream>
#include <thread>
#include <variant>

const std::string kData1 = "In Xanadu, did Kublai Khan...";
const std::string kData2 = "A stately pleasure dome decree...";

/*
 *       ___________________________________________________________
 *      |               |           |           |                   |   0
 *      | content type  |  length   |  version  |   sequence number |
 *      |_______________|___________|___________|___________________|
 *      |                                                           |   8
 *      |                                                           |
 *      |                                                           |   .
 *      |                                                           |   .
 *      |                       plaintext                           |   .
 *      |                                                           |   .
 *      |                                                           |   .
 *      |                                                           |
 *      |___________________________________________________________|
 *      |                                                           |
 *      |                            MAC                            |
 *      |___________________________________________________________|
 *      |                                                           |   4096
 *
 */

void Client(SecureDataChannel& channel) {
  channel.Write(Vec<u8>(kData1.begin(), kData1.end()));
  channel.Write(Vec<u8>(kData2.begin(), kData2.end()));
}

void Server(SecureDataChannel& channel) {
  Vec<u8> data = channel.Read(kData1.size());
  auto str = std::string{data.begin(), data.end()};
  std::clog << str << std::endl;
  Vec<u8> data1 = channel.Read(kData2.size());
  auto str1 = std::string{data1.begin(), data1.end()};
  std::clog << str1 << std::endl;
}

int main() {
  auto server_socket = SecureServerSocket{};
  auto channel1 = server_socket.CreateNewChannel();
  std::jthread t1 = std::jthread{[channel1] { Server(*channel1); }};
  sleep(1);
  // faccio partire prima il server
  auto client_socket = SecureClientSocket{};
  auto channel2 = client_socket.Connect();
  std::jthread t2 = std::jthread{[channel2] { Client(*channel2); }};
  t1.join();
  t2.join();
  // SerializeMessage(ClientHelloContent{});
}

