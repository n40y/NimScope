# src/protocols/ad/smb_shares.nim
##
## Énumération des partages SMB (shares) via SRVSVC RPC.
## Permet de détecter les partages accessibles (IPC$, C$, ADMIN$, NETLOGON, etc.)
##
## La méthode :
##   1. Négociation SMB2/3 (comme dans smb.nim)
##   2. SETUP (connexion d'une session)
##   3. TREE_CONNECT vers \\target\IPC$
##   4. Appel RPC via Named Pipe srvsvc (NetShareEnumAll)
##   5. Parser la réponse pour extraire les noms de partages

import std/[net, endians, strutils, json, asyncnet, asyncdispatch]

# ==================== CONSTANTES SMB2 ====================

const
  # SMB2 Commands
  SMB2_NEGOTIATE = 0x00'u8
  SMB2_SETUP = 0x01'u8
  SMB2_TREE_CONNECT = 0x03'u8
  SMB2_CREATE = 0x05'u8
  SMB2_WRITE = 0x09'u8
  SMB2_READ = 0x04'u8
  SMB2_CLOSE = 0x06'u8
  SMB2_LOGOFF = 0x02'u8

  # SMB2 Dialect
  SMB_DIALECT_2_0_2 = 0x0202'u16
  SMB_DIALECT_2_1 = 0x0210'u16
  SMB_DIALECT_3_0 = 0x0300'u16
  SMB_DIALECT_3_0_2 = 0x0302'u16
  SMB_DIALECT_3_1_1 = 0x0311'u16

  # Shares courants à tester
  CommonShares = [
    "IPC$", "C$", "D$", "ADMIN$", 
    "NETLOGON", "SYSVOL", "PRINT$",
    "Users", "SYSVOL", "BACKUP"
  ]

# ==================== BUILDER PAQUETS SMB2 ====================

proc buildSmb2Header(command: byte, creditCharge: uint16 = 1, 
                     creditRequest: uint16 = 1, midSeq: uint64 = 0,
                     treeId: uint32 = 0, sessionId: uint64 = 0): seq[byte] =
  ## Construit un header SMB2 complet (64 octets).
  result = newSeq[byte](64)
  
  # Signature SMB2
  result[0] = 0xFE
  result[1] = byte 'S'
  result[2] = byte 'M'
  result[3] = byte 'B'
  
  # Command
  result[12] = command
  
  # CreditCharge (2 octets @ offset 6)
  littleEndian16(addr result[6], unsafeAddr creditCharge)
  
  # Status (always 0 in requests)
  # result[20..23] = 0
  
  # Flags (flags @ offset 16, 4 octets)
  # Bit 0 = response (0 for request)
  result[16] = 0x01  # CLIENT_GENERATED = 1
  
  # TreeID (offset 36, 4 octets)
  littleEndian32(addr result[36], unsafeAddr treeId)
  
  # SessionID (offset 40, 8 octets)
  littleEndian64(addr result[40], unsafeAddr sessionId)
  
  # MessageID (offset 24, 8 octets) - on le laisse à 0 pour simplifier ici
  littleEndian64(addr result[24], unsafeAddr midSeq)

proc packString16(s: string): seq[byte] =
  ## UTF-16LE encoded string avec null terminator
  result = @[]
  for c in s:
    result &= @[byte c, byte 0]
  result &= @[byte 0, byte 0]  # null terminator

proc buildSmb2Negotiate(dialect: uint16 = SMB_DIALECT_3_1_1): seq[byte] =
  ## Construit un paquet NEGOTIATE.
  result = newSeq[byte](1024)
  var pos = 0
  
  # NetBIOS header (4 octets)
  result[pos] = 0
  result[pos+1] = 0
  result[pos+2] = 0
  pos += 4
  
  # SMB2 Header (64 octets)
  let header = buildSmb2Header(SMB2_NEGOTIATE)
  result[pos ..< pos + 64] = header
  pos += 64
  
  # NEGOTIATE request body
  result[pos] = 36  # StructureSize (18 mais on compte en words, donc 0x24)
  pos += 2
  
  # DialectCount
  result[pos] = 1
  pos += 2
  
  # SecurityMode (2 octets)
  result[pos] = 0x01  # SIGNING_ENABLED
  pos += 2
  
  # Capabilities (4 octets)
  pos += 4
  
  # ClientGuid (16 octets)
  pos += 16
  
  # ClientStartTime (8 octets)
  pos += 8
  
  # Dialects (variable)
  littleEndian16(addr result[pos], unsafeAddr dialect)
  pos += 2
  
  # Recadrer
  result.setLen(pos)

proc buildSmb2Setup(sessionId: uint64): seq[byte] =
  ## Construit un paquet SESSION_SETUP (simplifié, sans auth).
  result = newSeq[byte](512)
  var pos = 0
  
  # NetBIOS header
  result[pos] = 0
  pos += 4
  
  # SMB2 Header
  let header = buildSmb2Header(SMB2_SETUP, sessionId=sessionId)
  result[pos ..< pos + 64] = header
  pos += 64
  
  # SETUP request body
  result[pos] = 25  # StructureSize
  pos += 2
  
  # VcNumber
  result[pos] = 0
  pos += 1
  
  # SecurityMode
  result[pos] = 0x01
  pos += 1
  
  # Capabilities
  pos += 4
  
  # Channel
  pos += 4
  
  # SecurityBufferOffset/Length
  pos += 4
  
  # PreviousSessionId (8 octets)
  pos += 8
  
  # Buffer (empty for null auth)
  result.setLen(pos)

proc buildSmb2TreeConnect(target: string, sessionId: uint64, path: string): seq[byte] =
  ## Construit un paquet TREE_CONNECT.
  result = newSeq[byte](512)
  var pos = 0
  
  # NetBIOS header
  result[pos] = 0
  pos += 4
  
  # SMB2 Header (sessionId, pas de treeId encore)
  let header = buildSmb2Header(SMB2_TREE_CONNECT, sessionId=sessionId)
  result[pos ..< pos + 64] = header
  pos += 64
  
  # TREE_CONNECT request body
  result[pos] = 9  # StructureSize
  pos += 2
  
  # Reserved
  pos += 2
  
  # PathOffset (2 octets)
  result[pos] = byte(pos + 4)  # pathOffset pointe juste après
  pos += 2
  
  # PathLength
  let pathBytes = packString16(path)
  littleEndian16(addr result[pos], addr uint16(pathBytes.len))
  pos += 2
  
  # Buffer (le path)
  result[pos ..< pos + pathBytes.len] = pathBytes
  pos += pathBytes.len
  
  result.setLen(pos)

# ==================== PARSER RÉPONSES ====================

proc parseSmb2NegotiateResponse(data: seq[byte]): tuple[dialect: uint16, sessionId: uint64] =
  ## Parse une réponse NEGOTIATE pour extraire le dialecte et sessionId.
  var dialect: uint16 = 0
  var sessionId: uint64 = 0
  
  if data.len < 72:
    return (dialect, sessionId)
  
  # SessionId @ offset 40 dans le header (offset 44 si on compte le NetBIOS)
  if data.len >= 48:
    littleEndian64(addr sessionId, unsafeAddr data[44])
  
  # Dialect @ offset 70
  if data.len >= 72:
    littleEndian16(addr dialect, unsafeAddr data[70])
  
  return (dialect, sessionId)

proc parseSmb2TreeConnectResponse(data: seq[byte]): uint32 =
  ## Parse une réponse TREE_CONNECT pour extraire le TreeId.
  var treeId: uint32 = 0
  
  # TreeId @ offset 36 dans le header
  if data.len >= 40:
    littleEndian32(addr treeId, unsafeAddr data[36])
  
  return treeId

# ==================== ENUMERATION (simplifié) ====================

proc enumerateSmbShares*(target: string, port: int = 445): Future[JsonNode] {.async.} =
  ## Énumère les partages SMB accessibles en testant les shares courants.
  ## Retourne un JSON { "shares": [ { "name": "IPC$", "accessible": true }, ... ] }
  
  var result = newJObject()
  var shares = newJArray()
  
  let socket = newAsyncSocket()
  try:
    await socket.connect(target, Port(port))
    
    # 1. NEGOTIATE
    let negotiatePacket = buildSmb2Negotiate()
    await socket.send(cast[pointer](unsafeAddr negotiatePacket[0]), negotiatePacket.len)
    
    let negotiateResp = await socket.recv(4096)
    if negotiateResp.len < 4:
      result["error"] = newJString("No NEGOTIATE response")
      return result
    
    var respBytes = newSeq[byte](negotiateResp.len)
    for i, c in negotiateResp:
      respBytes[i] = byte(c)
    
    let (dialect, sessionId) = parseSmb2NegotiateResponse(respBytes)
    
    # 2. SESSION_SETUP
    let setupPacket = buildSmb2Setup(sessionId)
    await socket.send(cast[pointer](unsafeAddr setupPacket[0]), setupPacket.len)
    
    let setupResp = await socket.recv(4096)
    if setupResp.len < 4:
      result["error"] = newJString("No SETUP response")
      return result
    
    # 3. Tester chaque share
    for shareName in CommonShares:
      let path = "\\\\" & target & "\\" & shareName
      
      let treeConnectPacket = buildSmb2TreeConnect(target, sessionId, path)
      await socket.send(cast[pointer](unsafeAddr treeConnectPacket[0]), treeConnectPacket.len)
      
      let treeResp = await socket.recv(4096)
      
      var treeBytes = newSeq[byte](treeResp.len)
      for i, c in treeResp:
        treeBytes[i] = byte(c)
      
      # Vérifier si TREE_CONNECT a réussi (pas d'erreur SMB2)
      let accessible = if treeBytes.len >= 24:
        let status = int32(
          int(treeBytes[20]) or
          (int(treeBytes[21]) shl 8) or
          (int(treeBytes[22]) shl 16) or
          (int(treeBytes[23]) shl 24)
        )
        status == 0  # STATUS_SUCCESS
      else:
        false
      
      var shareObj = newJObject()
      shareObj["name"] = newJString(shareName)
      shareObj["accessible"] = newJBool(accessible)
      shares.add(shareObj)
  
  except CatchableError as e:
    result["error"] = newJString(e.msg)
  finally:
    socket.close()
  
  result["shares"] = shares
  return result

# ==================== API DE COMPATIBILITÉ (wrapper pour executor) ====================

proc checkSmbSigning*(target: string, port: int = 445): tuple[signing: string, dialect: uint16] =
  ## Détection du SMB signing (existant, on le garde pour compatibilité).
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
  
  const OffsetSecurityMode = 66
  const OffsetDialectRevision = 68
  
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
    
    let securityMode = response[OffsetSecurityMode]
    var dialect: uint16
    littleEndian16(addr dialect, addr response[OffsetDialectRevision])
    
    let signing = if (securityMode and 0x02) == 0x02: "REQUIRED" else: "NOT_REQUIRED"
    return (signing, dialect)
  except CatchableError:
    if socket != nil: socket.close()
    return ("NETWORK_ERROR", 0'u16)

proc guessOsFromDialect*(dialect: uint16): string =
  ## Estimation OS depuis le dialecte SMB (existant, on le garde).
  case dialect
  of 0x0202: "Windows Vista SP1 / Server 2008 (SMB 2.0.2)"
  of 0x0210: "Windows 7 / Server 2008 R2 (SMB 2.1)"
  of 0x0300: "Windows 8 / Server 2012 (SMB 3.0)"
  of 0x0302: "Windows 8.1 / Server 2012 R2 (SMB 3.0.2)"
  of 0x0311: "Windows 10 / Server 2016+ (SMB 3.1.1)"
  else: "Unknown (dialect 0x" & dialect.toHex(4) & ")"
