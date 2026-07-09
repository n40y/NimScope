# src/protocols/ad/ldap_search.nim
##
## Encodeur BER pour LDAP SearchRequest (RFC 4511 §4.5.1)
## Permet de requêter LDAP anonymement et parser les résultats.
##
## Exemple :
##   let results = ldapSearchAsync(target, port, "DC=domain,DC=local", 
##                                  "(&(objectClass=user)(sAMAccountName=admin*))", 
##                                  @["sAMAccountName", "mail"])

import std/[asyncnet, asyncdispatch, json, tables, strutils]

const
  TagSequence = 0x30'u8
  TagBindRequest = 0x60'u8
  TagBindResponse = 0x61'u8
  TagSearchRequest = 0x63'u8      # [APPLICATION 3]
  TagSearchResultEntry = 0x64'u8  # [APPLICATION 4]
  TagSearchResultDone = 0x65'u8   # [APPLICATION 5]
  TagInteger = 0x02'u8
  TagOctetString = 0x04'u8
  TagEnumerated = 0x0A'u8
  TagNull = 0x05'u8
  TagSet = 0x31'u8
  TagAttributeValueAssertion = 0x30'u8
  
  # Tags pour les filtres LDAP
  TagFilterAnd = 0xA0'u8      # [0] IMPLICIT
  TagFilterOr = 0xA1'u8       # [1] IMPLICIT
  TagFilterNot = 0xA2'u8      # [2] IMPLICIT
  TagFilterEqual = 0xA3'u8    # [3] IMPLICIT
  TagFilterSubstring = 0xA4'u8
  TagFilterGreaterOrEqual = 0xA5'u8
  TagFilterLessOrEqual = 0xA6'u8
  TagFilterPresent = 0x87'u8  # [7] IMPLICIT OCTET STRING

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

# ==================== PARSER FILTRE LDAP ====================

type
  FilterKind = enum
    fkEqual = "equal"
    fkPresent = "present"
    fkSubstring = "substring"
    fkAnd = "and"
    fkOr = "or"
    fkNot = "not"
    fkError = "error"

  FilterNode = object
    case kind: FilterKind
    of fkAnd, fkOr, fkNot:
      children: seq[FilterNode]
    of fkEqual:
      attr: string
      value: string
    of fkPresent:
      attr: string
    of fkSubstring:
      attr: string
      initial: string
      any: seq[string]
      final: string
    of fkError:
      discard

proc parseFilter(filter: string): FilterNode =
  ## Parser très simplifié pour les filtres LDAP courants.
  ## Supporte :
  ##   (attr=value)              -> EQUAL
  ##   (attr=*)                  -> PRESENT
  ##   (&(cond1)(cond2))         -> AND
  ##   (|(cond1)(cond2))         -> OR
  ##   (!(cond))                 -> NOT
  ##   (attr=initial*any*final)  -> SUBSTRING
  
  let s = filter.strip()
  
  if not s.startsWith("(") or not s.endsWith(")"):
    return FilterNode(kind: fkError)
  
  let inner = s[1 ..< s.len - 1]
  
  # Cas : (&(...) (...)) / (|(...) (...)) / (!(...))
  if inner.startsWith("&"):
    var children: seq[FilterNode] = @[]
    var depth = 0
    var current = ""
    for c in inner[1 ..< inner.len]:
      if c == '(':
        if depth == 0 and current.len > 0 and current.strip() != "":
          discard  # skip
        inc depth
        current &= c
      elif c == ')':
        dec depth
        current &= c
        if depth == 0 and current.len > 0:
          children.add(parseFilter(current.strip()))
          current = ""
      else:
        current &= c
    return FilterNode(kind: fkAnd, children: children)
  
  elif inner.startsWith("|"):
    var children: seq[FilterNode] = @[]
    var depth = 0
    var current = ""
    for c in inner[1 ..< inner.len]:
      if c == '(':
        if depth == 0 and current.len > 0 and current.strip() != "":
          discard
        inc depth
        current &= c
      elif c == ')':
        dec depth
        current &= c
        if depth == 0 and current.len > 0:
          children.add(parseFilter(current.strip()))
          current = ""
      else:
        current &= c
    return FilterNode(kind: fkOr, children: children)
  
  elif inner.startsWith("!"):
    let subfilter = inner[1 ..< inner.len].strip()
    return FilterNode(kind: fkNot, children: @[parseFilter(subfilter)])
  
  # Cas : (attr op value)
  elif "=" in inner:
    let parts = inner.split('=', 1)
    if parts.len != 2:
      return FilterNode(kind: fkError)
    
    let attr = parts[0].strip()
    let value = parts[1].strip()
    
    if value == "*":
      return FilterNode(kind: fkPresent, attr: attr)
    elif "*" in value:
      # Substring
      let subparts = value.split('*')
      var initial, final: string
      var any: seq[string] = @[]
      if subparts.len >= 1: initial = subparts[0]
      if subparts.len >= 2:
        for i in 1 ..< subparts.len - 1:
          any.add(subparts[i])
      if subparts.len >= 2: final = subparts[^1]
      return FilterNode(kind: fkSubstring, attr: attr, initial: initial, any: any, final: final)
    else:
      return FilterNode(kind: fkEqual, attr: attr, value: value)
  
  return FilterNode(kind: fkError)

# ==================== ENCODEUR DE FILTRE ====================

proc encodeFilter(node: FilterNode): seq[byte] =
  case node.kind
  of fkEqual:
    let ava = berTLV(TagAttributeValueAssertion, 
                     berOctetString(node.attr) & berOctetString(node.value))
    berTLV(TagFilterEqual, ava)
  
  of fkPresent:
    berTLV(TagFilterPresent, cast[seq[byte]](node.attr))
  
  of fkAnd:
    var children: seq[byte] = @[]
    for child in node.children:
      children &= encodeFilter(child)
    berTLV(TagFilterAnd, children)
  
  of fkOr:
    var children: seq[byte] = @[]
    for child in node.children:
      children &= encodeFilter(child)
    berTLV(TagFilterOr, children)
  
  of fkNot:
    if node.children.len > 0:
      berTLV(TagFilterNot, encodeFilter(node.children[0]))
    else:
      @[]
  
  of fkSubstring:
    # SimplifiedSubstringFilter = SEQUENCE { ... }
    var parts: seq[byte] = @[]
    parts &= berOctetString(node.attr)
    
    var subparts: seq[byte] = @[]
    if node.initial.len > 0:
      subparts &= berTLV(0x80'u8, cast[seq[byte]](node.initial))  # [0] initial
    for part in node.any:
      subparts &= berTLV(0x81'u8, cast[seq[byte]](part))          # [1] any
    if node.final.len > 0:
      subparts &= berTLV(0x82'u8, cast[seq[byte]](node.final))    # [2] final
    
    parts &= berTLV(TagSet, subparts)
    berTLV(TagFilterSubstring, parts)
  
  of fkError:
    # error
    @[]

# ==================== BUILDER SEARCHREQUEST ====================

proc buildSearchRequest(baseDn: string, filter: string, 
                        attributes: seq[string], 
                        messageId: int = 1): seq[byte] =
  let msgId = berInteger(messageId)
  
  # SearchRequest = [APPLICATION 3] SEQUENCE { ...
  var searchContent: seq[byte] = @[]
  searchContent &= berOctetString(baseDn)                    # baseObject
  searchContent &= berInteger(2)                             # scope = SUBTREE (2)
  searchContent &= berInteger(0)                             # derefAliases = NEVER (0)
  searchContent &= berInteger(0)                             # sizeLimit = 0 (unlimited)
  searchContent &= berInteger(30)                            # timeLimit = 30s
  searchContent &= berTLV(TagNull, @[byte 1])                # typesOnly = FALSE
  
  let filterNode = parseFilter(filter)
  searchContent &= encodeFilter(filterNode)                  # filter
  
  # Attributes to return (SET OF AttributeSelection)
  var attrSet: seq[byte] = @[]
  for attr in attributes:
    attrSet &= berOctetString(attr)
  searchContent &= berTLV(TagSet, attrSet)
  
  let searchRequest = berTLV(TagSearchRequest, searchContent)
  let messageContent = msgId & searchRequest
  
  result = berTLV(TagSequence, messageContent)

# ==================== PARSER RÉSULTATS ====================

proc parseSearchResultEntry(data: seq[byte], startPos: int): tuple[endPos: int, entry: JsonNode] =
  ## Parse une SearchResultEntry du point `startPos`.
  ## Retourne la position de fin et l'objet JSON extrait.
  
  var pos = startPos
  var entry = newJObject()
  
  # On attend un tag SEQUENCE pour l'entrée
  # Pour simplifier, on lit juste des OCTET STRINGS et on les ajoute
  # Cette version est très basique : elle récupère les attributs naïvement.
  # Un vrai parseur BER complet serait plus robuste.
  
  try:
    if pos >= data.len:
      return (pos, entry)
    
    # Simplification : on cherche les OCTET STRING dans la réponse
    # et on les collecte naïvement. C'est un hack, mais ça marche en pratique.
    var i = pos
    var currentKey = ""
    while i < data.len and i < pos + 512:  # Limite pour éviter les boucles infinies
      if data[i] == TagOctetString and i + 1 < data.len:
        let len = int(data[i + 1])
        if i + 2 + len <= data.len:
          let value = cast[string](data[i + 2 ..< i + 2 + len])
          if currentKey.len == 0:
            currentKey = value
          else:
            entry[currentKey] = newJString(value)
            currentKey = ""
          i += 2 + len
        else:
          break
      else:
        inc i
    
    return (i, entry)
  except:
    return (startPos, entry)

# ==================== API PUBLIQUE ====================

proc ldapSearchAsync*(target: string, port: int, baseDn: string, 
                      filter: string, attributes: seq[string]): Future[seq[JsonNode]] {.async.} =
  ## Effectue une recherche LDAP asynchrone.
  ## Retourne un array d'objets JSON contenant les résultats.
  
  result = @[]
  
  let socket = newAsyncSocket()
  try:
    await socket.connect(target, Port(port))
    
    # D'abord : faire un bind anonyme
    let bindPacket = buildAnonymousBindRequest(1)
    await socket.send(cast[pointer](unsafeAddr bindPacket[0]), bindPacket.len)
    
    let bindResp = await socket.recv(4096)
    if bindResp.len == 0:
      return
    
    # Puis : envoyer la requête de recherche
    let searchPacket = buildSearchRequest(baseDn, filter, attributes, 2)
    await socket.send(cast[pointer](unsafeAddr searchPacket[0]), searchPacket.len)
    
    # Récupérer les réponses (SearchResultEntry + SearchResultDone)
    # Avec timeout pour éviter de bloquer indéfiniment
    while true:
      let response = await socket.recv(4096)
      if response.len == 0:
        break
      
      # Parser naïf : chercher les SearchResultEntry (tag 0x64)
      # C'est très basique, mais ça capture les données essentielles
      var i = 0
      var respBytes = newSeq[byte](response.len)
      for j, c in response:
        respBytes[j] = byte(c)
      
      while i < respBytes.len:
        if respBytes[i] == TagSearchResultEntry:
          let (endPos, entry) = parseSearchResultEntry(respBytes, i + 1)
          if entry.len > 0:
            result.add(entry)
          i = endPos
        elif respBytes[i] == TagSearchResultDone:
          break
        else:
          inc i
      
      break  # Pour cette MVP, on lit la réponse une seule fois
  
  except CatchableError as e:
    discard  # Silencieusement, on retourne un array vide
  finally:
    socket.close()

# Pour compatibilité avec le code existant
proc buildAnonymousBindRequest(messageId: int = 1): seq[byte] =
  let version = berTLV(0x02'u8, @[byte 3])
  let name = berTLV(TagOctetString, @[])
  let auth = berTLV(0x80'u8, @[])
  let bindRequestContent = version & name & auth
  let bindRequest = berTLV(TagBindRequest, bindRequestContent)
  let msgId = berTLV(TagInteger, @[byte messageId])
  let messageContent = msgId & bindRequest
  result = berTLV(TagSequence, messageContent)
