# src/protocols/ad/smb.nim
##
## Module SMB pour audits Active Directory.
## Contient :
##   - Détection du SMB signing (check-signing)
##   - Énumération des partages (enumerate-shares via smb_shares.nim)
##   - Estimation de l'OS via le dialecte SMB

import std/[net, endians, json, asyncnet, asyncdispatch, strutils]
import ./smb_shares

export smb_shares  # Réexporte les procs de smb_shares

# Packet de négociation SMB2 pour détecter le signing
const smbNegotiatePacket: array[90, byte] = [
  byte 0x00, 0x00, 0x00, 0x56, 0xFE, 0x53, 0x4D, 0x42,
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x24, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x7F, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00
]

# Offsets dans SMB2 NEGOTIATE_RESPONSE (header SMB2 = 64 octets, payload ensuite) :
#   SecurityMode     @ 66  (2 octets)
#   DialectRevision  @ 68  (2 octets)
const
  OffsetSecurityMode = 66
  OffsetDialectRevision = 68

# ==================== SMB SIGNING CHECK ====================

proc checkSmbSigning*(target: string, port: int = 445): tuple[signing: string, dialect: uint16] =
  ## Vérifie si le SMB signing est requis, et retourne aussi le dialecte
  ## négocié (utile pour estimer la version d'OS).
  ## 
  ## Retourne un tuple (signing_status, dialect_code) où :
  ##   - signing_status : "REQUIRED", "NOT_REQUIRED", "PORT_CLOSED", "NETWORK_ERROR", "INVALID_RESPONSE"
  ##   - dialect_code : 0x0202, 0x0210, 0x0300, 0x0302, 0x0311, etc.
  
  var socket = newSocket()
  try:
    socket.connect(target, Port(port), timeout = 2500)
  except CatchableError:
    return ("PORT_CLOSED", 0'u16)

  try:
    discard socket.send(addr smbNegotiatePacket[0], smbNegotiatePacket.len)

    var response: array[1024, byte]
    let bytesReceived = socket.recv(addr response[0], 1024)
    socket.close()

    if bytesReceived < OffsetDialectRevision + 2:
      return ("INVALID_RESPONSE", 0'u16)

    # SecurityMode est un champ 16 bits, mais seul le bit de poids faible
    # (SIGNING_REQUIRED = 0x02) nous intéresse ici -> on lit l'octet bas (LE).
    let securityMode = response[OffsetSecurityMode]
    var dialect: uint16
    littleEndian16(addr dialect, addr response[OffsetDialectRevision])

    let signing = if (securityMode and 0x02) == 0x02: "REQUIRED" else: "NOT_REQUIRED"
    return (signing, dialect)
  except CatchableError:
    if socket != nil: socket.close()
    return ("NETWORK_ERROR", 0'u16)

# ==================== ENUMERATION DE PARTAGES ====================

proc enumerateSmbSharesAsync*(target: string, port: int = 445): Future[JsonNode] {.async.} =
  ## Énumère les partages SMB accessibles.
  ## Retourne un JSON { "shares": [ { "name": "IPC$", "accessible": true }, ... ] }
  ##
  ## Utilise smb_shares.enumerateSmbShares en mode asynchrone.
  return await enumerateSmbShares(target, port)

# ==================== ESTIMATION OS (pure Nim, sans NetAPI) ====================

proc guessOsFromDialect*(dialect: uint16): string =
  ## Estimation approximative à partir du dialecte SMB2/3 négocié.
  ## Moins précis qu'un vrai fingerprint, mais portable et suffisant
  ## pour un rapport d'audit.
  case dialect
  of 0x0202: "Windows Vista SP1 / Server 2008 (SMB 2.0.2)"
  of 0x0210: "Windows 7 / Server 2008 R2 (SMB 2.1)"
  of 0x0300: "Windows 8 / Server 2012 (SMB 3.0)"
  of 0x0302: "Windows 8.1 / Server 2012 R2 (SMB 3.0.2)"
  of 0x0311: "Windows 10 / Server 2016+ (SMB 3.1.1)"
  else: "Inconnu (dialecte 0x" & dialect.toHex(4) & ")"

# ==================== WRAPPER COMPATIBILITÉ ====================

# Pour garder la compatibilité avec executor.nim qui appelle getRemoteOsVersion()
proc getRemoteOsVersion*(target: string, port: int = 445): string =
  ## Wrapper pour estimer l'OS sans appel async.
  ## Utile pour executor.nim qui n'est pas async dans smb.nim.
  let (_, dialect) = checkSmbSigning(target, port)
  return guessOsFromDialect(dialect)
