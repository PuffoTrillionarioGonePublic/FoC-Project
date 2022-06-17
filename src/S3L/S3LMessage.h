#ifndef S3L_RECORD_H
#define S3L_RECORD_H

#include "../Crypto/api.hh"
#include "NetworkBuffer.h"
#include "S3LHeader.h"
#include "SizeCalculator.h"
#include "constants.h"
#include "../util.h"
#include "utility.h"

/// aggiornare l'header ogni volta che si modifica il content

struct S3LMessage {
  /// ogni message deve specificare come deve essere serializzato
  /// in formato binario compatibile con la rete
  [[nodiscard]] virtual NetworkBuffer Serialize() const = 0;
  /// ogni tipo di message deve contenere un metodo
  /// che permetta di verificare se effettivamente
  /// il message e` valido o meno, altrimenti deve essere lanciata una eccezione
  virtual ~S3LMessage() = default;
};

#endif  // S3L_RECORD_H
