#ifndef S3L_IOCOMMUNICATION_H
#define S3L_IOCOMMUNICATION_H

#include "constants.h"
#include "../util.h"
#include <barrier>
#include <exception>
#include <optional>
#include <stdexcept>

/// un oggetto IOChannel e` un oggetto sul quale e` possibile scrivere,
/// leggere, chiudere la comunicazione o verificare che lo sia.
class IOChannel {
 public:
  /// questa funzione continua e` bloccante e continua ad aspettare
  /// byte finche` non ne riceve esattamente n
  virtual Vec<u8> Read(size_t n) = 0;
  virtual void Write(const Vec<u8> &buf) = 0;
  virtual bool IsClosed() = 0;
  virtual void Close() noexcept = 0;
  virtual ~IOChannel() = default;
};

#endif  // S3L_IOCOMMUNICATION_H
