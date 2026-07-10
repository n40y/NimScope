# src/protocols/ad/ldap_search.nim
## Encodeur BER + Search LDAP (RFC 4511)
## Utilisé pour l'énumération anonyme (users, SPNs, etc.)

import std/[asyncnet, asyncdispatch, json, strutils]

const
  TagSequence         = 0x30'u8
  TagBindRequest      = 0x60'u8
  TagSearchRequest    = 0x63'u8
  TagInteger          = 0x02'u8
  TagOctetString      = 0x04'u8
  TagNull             = 0x05'u8
  TagSet              = 0x31'u8

  # Tags futurs — on les marque explicitement comme utilisés pour supprimer le hint
  TagSearchResultEntry {.used.} = 0x64'u8
  TagSearchResultDone  {.used.} = 0x65'u8

# ==================== HELPERS BER ====================

proc berLength(n: int): seq[byte] =
  if n < 0x80:
    result = @[byte n]
  else:
    var bytes: seq[byte] = @[]
    var v = n
    while v > 0:
      bytes.insert(byte(v and 0xFF), 0)
      v = v shr 8
    result = @[byte(0x80 or bytes.len)] & bytes

proc berTLV(tag: byte, content: seq[byte]): seq[byte] =
  @[tag] & berLength(content.len) & content

proc berInteger(n: int): seq[byte] =
  if n == 0:
    berTLV(TagInteger, @[byte 0])
  else:
    var bytes: seq[byte] = @[]
    var v = n
    while v > 0:
      bytes.insert(byte(v and 0xFF), 0)
      v = v shr 8
    if (bytes[0] and 0x80) != 0:
      bytes.insert(0'u8, 0)
    berTLV(TagInteger, bytes)

proc berOctetString(s: string): seq[byte] =
  berTLV(TagOctetString, cast[seq[byte]](s))

proc berNull(): seq[byte] =
  berTLV(TagNull, @[])

# ==================== BIND ANONYME ====================

proc buildAnonymousBindRequest(messageId: int = 1): seq[byte] =
  let version = berTLV(TagInteger, @[byte 3])
  let name = berOctetString("")
  let auth = berTLV(0x80'u8, @[])          # Simple bind avec mot de passe vide

  let bindContent = version & name & auth
  let bindRequest = berTLV(TagBindRequest, bindContent)

  let msgId = berInteger(messageId)
  let messageContent = msgId & bindRequest

  result = berTLV(TagSequence, messageContent)

# ==================== SEARCH REQUEST ====================

proc buildSearchRequest(baseDn: string, filter: string, 
                        attributes: seq[string], 
                        messageId: int = 1): seq[byte] =
  # Version simplifiée (on améliore plus tard)
  let msgId = berInteger(messageId)

  var searchContent: seq[byte] = @[]
  searchContent &= berOctetString(baseDn)           # baseObject
  searchContent &= berInteger(2)                    # scope = wholeSubtree
  searchContent &= berInteger(0)                    # derefAliases
  searchContent &= berInteger(0)                    # sizeLimit
  searchContent &= berInteger(30)                   # timeLimit
  searchContent &= berNull()                        # typesOnly = false

  # Filter simplifié (on accepte le filtre brut pour l'instant)
  searchContent &= berOctetString(filter)           # TODO: vrai encodeur de filtre

  # Attributes
  var attrSet: seq[byte] = @[]
  for attr in attributes:
    attrSet &= berOctetString(attr)
  searchContent &= berTLV(TagSet, attrSet)

  let searchRequest = berTLV(TagSearchRequest, searchContent)
  let messageContent = msgId & searchRequest

  result = berTLV(TagSequence, messageContent)

# ==================== LDAP SEARCH ASYNC ====================

proc ldapSearchAsync*(target: string, port: int, baseDn: string, 
                      filter: string, attributes: seq[string]): Future[seq[JsonNode]] {.async.} =
  result = @[]

  let socket = newAsyncSocket()
  try:
    await socket.connect(target, Port(port))

    # 1. Bind anonyme
    let bindPacket = buildAnonymousBindRequest(1)
    await socket.send(cast[pointer](unsafeAddr bindPacket[0]), bindPacket.len)

    let bindResp = await socket.recv(4096)
    if bindResp.len == 0:
      return

    # 2. Search Request
    let searchPacket = buildSearchRequest(baseDn, filter, attributes, 2)
    await socket.send(cast[pointer](unsafeAddr searchPacket[0]), searchPacket.len)

    # 3. Récupération des résultats (version MVP très simplifiée)
    let response = await socket.recv(8192)
    if response.len == 0:
      return

    # Parser très basique pour l'instant (on l'améliorera)
    var entries: seq[JsonNode] = @[]
    # Pour le moment on retourne au moins quelque chose si bind OK
    if response.len > 100:  # heuristique grossière
      var dummy = newJObject()
      dummy["status"] = newJString("partial_results")
      entries.add(dummy)
    
    result = entries

  except CatchableError:
    discard
  finally:
    socket.close()
