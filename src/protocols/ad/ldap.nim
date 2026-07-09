# src/protocols/ad/ldap.nim
##
## Implémentation LDAPv3 pure Nim (aucune dépendance winim => multiplateforme).
## On n'implémente que le sous-ensemble de BER/ASN.1 nécessaire au bind anonyme :
##   LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE {...} }
##   BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER, name OCTET STRING,
##                                               authentication [0] OCTET STRING (simple) }
## Référence : RFC 4511.

import std/[asyncnet, asyncdispatch, net, json]

const
  TagSequence = 0x30'u8
  TagBindRequest = 0x60'u8   # [APPLICATION 0], constructed
  TagBindResponse = 0x61'u8  # [APPLICATION 1], constructed
  TagInteger = 0x02'u8
  TagOctetString = 0x04'u8
  TagEnumerated = 0x0A'u8
  TagAuthSimple = 0x80'u8    # [0], primitive (context-specific)

# ==================== ENCODAGE BER ====================

proc berLength(n: int): seq[byte] =
  ## Encode une longueur BER. On reste en "forme courte" (<128 octets),
  ## largement suffisant pour un BindRequest anonyme.
  if n < 0x80:
    result = @[byte n]
  else:
    # Forme longue : rarement nécessaire ici, mais on la gère par sécurité.
    var bytes: seq[byte] = @[]
    var v = n
    while v > 0:
      bytes.insert(byte(v and 0xFF), 0)
      v = v shr 8
    result = @[byte(0x80 or bytes.len)] & bytes

proc berTLV(tag: byte, content: seq[byte]): seq[byte] =
  @[tag] & berLength(content.len) & content

proc buildAnonymousBindRequest(messageId: int = 1): seq[byte] =
  ## Construit le paquet complet : version=3, name="", auth simple vide.
  let version = berTLV(TagInteger, @[byte 3])
  let name = berTLV(TagOctetString, @[])          # DN vide = bind anonyme
  let auth = berTLV(TagAuthSimple, @[])            # mot de passe vide

  let bindRequestContent = version & name & auth
  let bindRequest = berTLV(TagBindRequest, bindRequestContent)

  let msgId = berTLV(TagInteger, @[byte messageId])
  let messageContent = msgId & bindRequest

  result = berTLV(TagSequence, messageContent)

# ==================== DÉCODAGE BER (minimal) ====================

proc readBerLength(data: seq[byte], pos: var int): int =
  let first = data[pos]
  inc pos
  if (first and 0x80) == 0:
    return int(first)
  let numBytes = int(first and 0x7F)
  result = 0
  for i in 0 ..< numBytes:
    result = (result shl 8) or int(data[pos])
    inc pos

proc parseBindResponseResultCode(data: seq[byte]): int =
  ## Parcourt la LDAPMessage reçue jusqu'au resultCode du BindResponse.
  ## Retourne -1 si le paquet est malformé ou tronqué.
  try:
    var pos = 0
    if data[pos] != TagSequence: return -1
    inc pos
    discard readBerLength(data, pos)          # longueur totale, non utilisée ici

    if data[pos] != TagInteger: return -1     # messageID
    inc pos
    let idLen = readBerLength(data, pos)
    pos += idLen

    if data[pos] != TagBindResponse: return -1
    inc pos
    discard readBerLength(data, pos)          # longueur du BindResponse

    if data[pos] != TagEnumerated: return -1  # resultCode
    inc pos
    let codeLen = readBerLength(data, pos)
    result = 0
    for i in 0 ..< codeLen:
      result = (result shl 8) or int(data[pos])
      inc pos
  except IndexDefect:
    result = -1

# ==================== API PUBLIQUE ====================

proc checkLdapPort*(target: string, port: int): bool =
  var socket = newSocket()
  try:
    socket.connect(target, Port(port), timeout = 1000)
    socket.close()
    true
  except CatchableError:
    false

proc tryAnonymousBind*(target: string, port: int): Future[string] {.async.} =
  ## Tente un bind anonyme LDAPv3. Retourne un statut compatible avec
  ## AuditStatus ("SUCCESS", "PORT_CLOSED", "BIND_DENIED", "ERROR")
  ## via le helper toStatus() de executor.nim.
  if not checkLdapPort(target, port):
    return "PORT_CLOSED"

  let socket = newAsyncSocket()
  try:
    await socket.connect(target, Port(port))

    let packet = buildAnonymousBindRequest()
    await socket.send(cast[pointer](unsafeAddr packet[0]), packet.len)

    let response = await socket.recv(1024)
    if response.len == 0:
      return "ERROR"

    var respBytes = newSeq[byte](response.len)
    for i, c in response:
      respBytes[i] = byte(c)

    let code = parseBindResponseResultCode(respBytes)
    # resultCode 0 = success (RFC 4511 §4.1.9)
    if code == 0: return "SUCCESS"
    else: return "BIND_DENIED"
  except CatchableError:
    return "ERROR"
  finally:
    socket.close()

proc queryLdap*(target: string, port: int, baseDn: string, filter: string,
                attributes: seq[string]): JsonNode =
  ## TODO (phase 2) : encodage BER du SearchRequest + décodage des
  ## SearchResultEntry. Nécessite un parseur de filtre LDAP
  ## ((&(objectClass=user)...)) vers sa forme BER — je m'en occupe
  ## dans un prochain message dédié.
  result = newJArray()
