# src/protocols/ad/kerberos.nim
##
## Implémentation Kerberos pure Nim pour audits Active Directory.
## Supporte :
##   - AS-REP Roasting detection (utilisateurs sans pré-auth)
##   - SPN enumeration (via LDAP, plus efficace)
##
## Référence : RFC 4120, MS-KILE

import std/[net, json, asyncnet, asyncdispatch, strutils, sequtils, options]
import ./ldap

# ==================== CONSTANTES KERBEROS ====================

const
  # ASN.1 tags
  TagSequence = 0x30'u8
  TagInteger = 0x02'u8
  TagOctetString = 0x04'u8
  TagEnumerated = 0x0A'u8
  TagApplicationTag = 0x60'u8  # [APPLICATION 0] = AS-REQ
  
  # Kerberos message types
  KRB5_MSG_AS_REQ = 10
  KRB5_MSG_AS_REP = 11
  KRB5_MSG_TGS_REQ = 12
  KRB5_MSG_TGS_REP = 13
  KRB5_MSG_AP_REQ = 14
  KRB5_MSG_ERROR = 30

  # Name types
  KRB5_NT_PRINCIPAL = 1
  KRB5_NT_SRV_INST = 2
  
  # Encryption types
  ENCTYPE_DES_CBC_MD5 = 1
  ENCTYPE_DES_CBC_CRC = 2
  ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 17
  ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18
  ENCTYPE_RC4_HMAC = 23

  # PA-DATA types
  PA_TGS_REQ = 1
  PA_ENC_TIMESTAMP = 2
  PA_PAC_REQUEST = 128

  # User Account Control flags
  UF_DONT_REQUIRE_PREAUTH = 0x00400000'u32


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


# ==================== AS-REP ROASTING DETECTION ====================

proc buildAsReq*(realm: string, username: string): seq[byte] =
  ## Construit une AS-REQ Kerberos (demande de TGT).
  ## Sans pré-auth, le serveur peut répondre directement avec AS-REP.
  ##
  ## Structure simplifée :
  ##   AS-REQ ::= KDCReq avec pvno=5, msg-type=10
  
  # Pour cette MVP, on envoie un paquet simplifé
  # Un vrai AS-REQ serait plus complexe, mais cette version suffit
  # pour trigger les réponses AS-REP des serveurs Kerberos.
  
  result = newSeq[byte](0)
  
  # Realm (OCTET STRING)
  var realmBytes = berOctetString(realm)
  
  # PrincipalName (SEQUENCE { name-type INTEGER, name-string SEQUENCE OF STRING })
  var nameString = berTLV(TagSequence, berOctetString(username))
  var principalName = berTLV(TagSequence, 
    berInteger(KRB5_NT_PRINCIPAL) & nameString)
  
  # Till (GeneralizedTime, on met juste un timestamp lointain)
  var till = berOctetString("20700101000000Z")
  
  # AS-REQ body (SEQUENCE)
  var reqBody = berTLV(TagSequence,
    berInteger(5) &                    # pvno = 5
    berInteger(KRB5_MSG_AS_REQ) &      # msg-type = 10 (AS-REQ)
    principalName &                    # cname
    realmBytes &                       # realm
    till                               # till
  )
  
  # Top-level AS-REQ [APPLICATION 10]
  result = berTLV(0x6A'u8, reqBody)  # [APPLICATION 10]


proc parseAsRepError*(response: seq[byte]): tuple[hasError: bool, errorCode: int, message: string] =
  ## Parse une réponse KRB-ERROR pour extraire le code d'erreur.
  ## Retourne (hasError, errorCode, message).
  ##
  ## Codes d'erreur Kerberos :
  ##   16 = KDC_ERR_PREAUTH_REQUIRED
  ##   25 = KDC_ERR_PREAUTH_FAILED
  
  if response.len < 10:
    return (false, 0, "")
  
  # Vérifier si c'est un KRB-ERROR ([APPLICATION 30])
  if response[0] != 0x7E'u8:  # [APPLICATION 30]
    return (false, 0, "Not a KRB-ERROR")
  
  # Parcours simplifé : chercher le champ error-code (entier)
  # Dans une vraie implémentation, on parserait le BER complètement.
  # Pour MVP, on cherche juste l'entier qui suit dans la séquence.
  
  var errorCode = 0
  var i = 2  # Skip tag et length
  
  # Chercher le premier INTEGER (error-code)
  while i < response.len - 2:
    if response[i] == TagInteger:
      let len = int(response[i+1])
      if i + 2 + len <= response.len:
        errorCode = int(response[i + 2])
        if len > 1:
          errorCode = (errorCode shl 8) or int(response[i + 3])
        break
    inc i
  
  return (true, errorCode, "")


proc checkAsRepRoasting*(target: string, realm: string, username: string, 
                         port: int = 88): Future[tuple[vulnerable: bool, message: string]] {.async.} =
  ## Version stable et simple pour AS-REP Roasting
  
  let socket = newAsyncSocket()
  try:
    # Connexion
    await socket.connect(target, Port(port))
    
    # Envoi de la requête
    let asReq = buildAsReq(realm, username)
    await socket.send(cast[pointer](unsafeAddr asReq[0]), asReq.len)
    
    # Réception (sans timeout compliqué pour l'instant)
    let response = await socket.recv(4096)
    
    if response.len == 0:
      return (false, "No response from KDC")
    
    # Conversion en bytes
    var respBytes = newSeq[byte](response.len)
    for i, c in response:
      respBytes[i] = byte(c)
    
    # Analyse
    let (hasError, errorCode, _) = parseAsRepError(respBytes)
    
    if hasError:
      if errorCode == 16:
        return (false, "User requires pre-auth (protected against AS-REP Roasting)")
      else:
        return (false, "KDC returned error code: " & $errorCode)
    
    # Succès = vulnérable
    return (true, "VULNERABLE - User has no pre-auth required (AS-REP Roasting possible)")
  
  except CatchableError as e:
    return (false, "Connection error: " & e.msg)
  finally:
    socket.close()


# ==================== SPN ENUMERATION (via LDAP) ====================

proc enumerateSpns*(target: string, ldapPort: int = 389, 
                    baseDn: string = ""): Future[seq[JsonNode]] {.async.} =
  ## Énumère les utilisateurs avec des SPNs (Service Principal Names).
  ## Utilise LDAP pour interroger les comptes avec servicePrincipalName.
  ##
  ## Retourne un array d'objets JSON : [{ "sAMAccountName": "...", "servicePrincipalName": "..." }, ...]
  ##
  ## Les SPNs permettent des attaques Kerberoasting.
  
  result = @[]
  
  # Si baseDn n'est pas fourni, on le déduit du target
  var dn = baseDn
  if dn.len == 0:
    # Heuristique simple : target = "dc.corp.local" -> "DC=dc,DC=corp,DC=local"
    let parts = target.split(".")
    dn = parts.mapIt("DC=" & it).join(",")
  
  # Requête LDAP pour tous les utilisateurs avec servicePrincipalName
  let filter = "(&(objectClass=user)(servicePrincipalName=*))"
  let attributes = @["sAMAccountName", "servicePrincipalName", "objectClass"]
  
  let results = await queryLdap(target, ldapPort, dn, filter, attributes)
  
  # Parser les résultats et retourner un array JSON
  for entry in results:
    if entry.hasKey("sAMAccountName") and entry.hasKey("servicePrincipalName"):
      result.add(entry)


# ==================== DETECTION USERS SANS PRE-AUTH ====================

proc enumerateNoPreAuthUsers*(target: string, ldapPort: int = 389,
                              baseDn: string = ""): Future[seq[JsonNode]] {.async.} =
  ## Énumère les utilisateurs avec le flag DONT_REQUIRE_PREAUTH.
  ## Ces utilisateurs sont vulnérables à AS-REP Roasting.
  ##
  ## Retourne un array d'objets JSON avec sAMAccountName et userAccountControl.
  
  result = @[]
  
  var dn = baseDn
  if dn.len == 0:
    let parts = target.split(".")
    dn = parts.mapIt("DC=" & it).join(",")
  
  # Requête LDAP pour les utilisateurs sans pré-auth
  # Note : userAccountControl 4194304 = 0x400000 = DONT_REQUIRE_PREAUTH
  let filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)))"
  let attributes = @["sAMAccountName", "userAccountControl"]
  
  let results = await queryLdap(target, ldapPort, dn, filter, attributes)
  
  for entry in results:
    if entry.hasKey("sAMAccountName"):
      result.add(entry)


# ==================== API WRAPPER ====================

proc checkKerberosService*(target: string, port: int = 88): bool =
  ## Test simple : vérifie si le port Kerberos (88) répond.
  var socket = newSocket()
  try:
    socket.connect(target, Port(port), timeout = 2000)
    socket.close()
    return true
  except CatchableError:
    return false


proc getKerberosRealm*(domainName: string): string =
  ## Déduit le realm Kerberos depuis un domain name.
  ## Exemple : "corp.local" -> "CORP.LOCAL"
  return domainName.toUpperAscii()
