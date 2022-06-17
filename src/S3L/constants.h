#ifndef S3L_CONSTANTS_H
#define S3L_CONSTANTS_H

const int kMacLength = 32;
const int kSha256Length = 32;
const int kIvLength = 16;
const int kAuthKeyLength = 16;
const int kSymmetricKeyLength = 16;

enum HandshakePayload {
  kClientHello,
  kServerHello,
  kShutdown,
  kData,
  kBadConnection,
  kClientFinished
};

#endif
