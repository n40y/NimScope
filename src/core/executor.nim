# src/core/executor.nim
##
## Révision : le `case tmp.protocol` unique devient une table de dispatch
## async, indexée par Protocol. Ajouter Kerberos ou une nouvelle action
## LDAP = écrire un proc `runXxx` + l'enregistrer dans `handlers`,
## sans toucher au reste du fichier.

import std/[asyncdispatch, strutils, json, tables, httpclient]
import ./types, ./logger
import ../protocols/ldap
import ../protocols/ad/smb
import ../protocols/ad/kerberos

type
  AsyncProtocolHandler = proc(tmp: Template, target: string, cfg: AdConfig): Future[AuditResult] {.gcsafe.}

## NOTE DE MIGRATION : ldap.nim / smb.nim renvoient encore des `string`
## ("SUCCESS", "PORT_CLOSED", ...) hérités de la version précédente.
## Le temps de les migrer vers AuditStatus, ce helper fait la conversion
## ici plutôt que de casser leur API tout de suite.
proc toStatus(s: string): AuditStatus =
  try: parseEnum[AuditStatus](s)
  except ValueError: stError

# ==================== HANDLER: LDAP ====================

proc runLdap(tmp: Template, target: string, cfg: AdConfig): Future[AuditResult] {.async.} =
  var res = newAuditResult(target, tmp.id, protoLdap, tmp.action)
  res.severity = parseSeverity(tmp.info.severity)

  let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.ldap
  let baseDn = cfg.ldap_queries.base_dn

  case tmp.action
  of "anonymous-bind":
    let bindStatus = toStatus(await tryAnonymousBind(target, port))
    res.status = bindStatus
    if bindStatus == stSuccess:
      res.message = "[" & tmp.id & "] " & tmp.info.name & " - VULNERABILITY CONFIRMED!"
      logSuccess(target, res.message)
    else:
      res.message = "[" & tmp.id & "] not vulnerable (" & $bindStatus & ")"
      if cfg.output.verbose: logFail(target, res.message)

  of "query-users", "query-spns", "query-passwords":
    var filter = "(objectClass=user)"
    var attrs = @["sAMAccountName", "description"]

    case tmp.action
    of "query-spns":
      filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
      attrs.add("servicePrincipalName")
    of "query-passwords":
      filter = "(&(objectClass=user)(|(description=*pass*)(description=*password*)(description=*pwd*)))"
    else: discard

    let data = await queryLdap(target, port, baseDn, filter, attrs)

    if data.len > 0:
      res.status = stVulnerable
      var jsonArray = newJArray()
      for entry in data:
        jsonArray.add(entry)
      res.details = jsonArray
      res.message = "[" & tmp.id & "] " & tmp.info.name & " - Looted " & $data.len & " entries!"
      logSuccess(target, res.message)
      if cfg.output.verbose:
        for entry in data:
          logInfo("Extracted:\n" & entry.pretty())
    else:
      res.status = stFailed
      res.message = "[" & tmp.id & "] " & tmp.info.name & " - No data leaked (Null Session queries disabled)."
      if cfg.output.verbose: logFail(target, res.message)

  else:
    res.status = stError
    res.message = "Action LDAP inconnue : " & tmp.action
    logError(res.message)

  return res

# ==================== HANDLER: SMB ====================

proc runSmb(tmp: Template, target: string, cfg: AdConfig): Future[AuditResult] {.async.} =
  var res = newAuditResult(target, tmp.id, protoSmb, tmp.action)
  res.severity = parseSeverity(tmp.info.severity)

  case tmp.action
  of "check-signing":
    let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.smb
    let (signingStatus, dialect) = checkSmbSigning(target, port)

    # On ne construit le fragment "OS: ..." que si on a réellement reçu
    # une réponse exploitable (dialect != 0). Sinon "OS: Unknown (dialect 0x0000)"
    # n'apporte rien et pollue le message pour rien.
    let hasValidResponse = signingStatus in ["NOT_REQUIRED", "REQUIRED"]
    let osVer = if hasValidResponse: guessOsFromDialect(dialect) else: ""
    res.osVersion = osVer

    case signingStatus
    of "NOT_REQUIRED":
      res.status = stVulnerable
      res.message = "[" & tmp.id & "] " & tmp.info.name & " - OS: " & osVer & " - SIGNING NOT REQUIRED"
      logSuccess(target, res.message)
    of "REQUIRED":
      res.status = stFailed
      res.message = "[" & tmp.id & "] not vulnerable (Signing required) - OS: " & osVer
      if cfg.output.verbose: logFail(target, res.message)
    else:
      res.status = stError
      res.message = "[" & tmp.id & "] unable to verify (" & signingStatus & ")"
      if cfg.output.verbose: logFail(target, res.message)

  of "enumerate-shares":
    let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.smb
    let sharesData = await enumerateSmbSharesAsync(target, port)
    
    if sharesData.hasKey("shares"):
      let shares = sharesData["shares"]
      var accessibleCount = 0
      for share in shares:
        if share.hasKey("accessible") and share["accessible"].getBool():
          inc accessibleCount
      
      if accessibleCount > 0:
        res.status = stVulnerable
        res.details = sharesData
        res.message = "[" & tmp.id & "] " & tmp.info.name & " - Found " & $accessibleCount & " accessible shares!"
        logSuccess(target, res.message)
      else:
        res.status = stFailed
        res.message = "[" & tmp.id & "] No accessible shares found"
        if cfg.output.verbose: logFail(target, res.message)
    else:
      res.status = stError
      res.message = "[" & tmp.id & "] Unable to enumerate shares"
      logError(res.message)

  else:
    res.status = stError
    res.message = "Action SMB inconnue : " & tmp.action
    logError(res.message)

  return res

# ==================== HANDLER: KERBEROS ====================

proc runKerberos(tmp: Template, target: string, cfg: AdConfig): Future[AuditResult] {.async.} =
  var res = newAuditResult(target, tmp.id, protoKerberos, tmp.action)
  res.severity = parseSeverity(tmp.info.severity)

  let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.kerberos
  let realm = getKerberosRealm(target)

  case tmp.action
  of "enumerate-spns":
    # Énumère les utilisateurs avec SPNs (vulnérables au Kerberoasting)
    let baseDn = cfg.ldap_queries.base_dn
    let spnUsers = await enumerateSpns(target, cfg.ad_ports.ldap, baseDn)
    
    if spnUsers.len > 0:
      res.status = stVulnerable
      var jsonArray = newJArray()
      for entry in spnUsers:
        jsonArray.add(entry)
      res.details = jsonArray
      res.message = "[" & tmp.id & "] " & tmp.info.name & " - Found " & $spnUsers.len & " accounts vulnerable to Kerberoasting!"
      logSuccess(target, res.message)
      if cfg.output.verbose:
        for entry in spnUsers:
          logInfo("SPN User:\n" & entry.pretty())
    else:
      res.status = stFailed
      res.message = "[" & tmp.id & "] No SPN users found"
      if cfg.output.verbose: logFail(target, res.message)

  of "enumerate-no-preauth":
    # Énumère les utilisateurs sans pré-auth (vulnérables à AS-REP Roasting)
    let baseDn = cfg.ldap_queries.base_dn
    let noPreAuthUsers = await enumerateNoPreAuthUsers(target, cfg.ad_ports.ldap, baseDn)
    
    if noPreAuthUsers.len > 0:
      res.status = stVulnerable
      var jsonArray = newJArray()
      for entry in noPreAuthUsers:
        jsonArray.add(entry)
      res.details = jsonArray
      res.message = "[" & tmp.id & "] " & tmp.info.name & " - Found " & $noPreAuthUsers.len & " accounts vulnerable to AS-REP Roasting!"
      logSuccess(target, res.message)
      if cfg.output.verbose:
        for entry in noPreAuthUsers:
          logInfo("No-PreAuth User:\n" & entry.pretty())
    else:
      res.status = stFailed
      res.message = "[" & tmp.id & "] No users without pre-auth found"
      if cfg.output.verbose: logFail(target, res.message)

  else:
    res.status = stError
    res.message = "Action Kerberos inconnue : " & tmp.action
    logError(res.message)

  return res

# ==================== HANDLER: HTTP (cloud) ====================

proc runHttp(tmp: Template, target: string, cfg: AdConfig): Future[AuditResult] {.async.} =
  var res = newAuditResult(target, tmp.id, protoHttp, tmp.action)
  res.severity = parseSeverity(tmp.info.severity)

  let client = newAsyncHttpClient(userAgent = "NimScope/0.1")
  let url =
    if target.startsWith("http"): target
    elif target == "169.254.169.254": "http://" & target & "/latest/meta-data/"
    else: "https://" & target & ".s3.amazonaws.com"

  try:
    if cfg.output.verbose: logInfo("Requête HTTP GET asynchrone vers : " & url)
    let response = await client.get(url)

    if tmp.action == "check-acl":
      if response.code == Http200:
        res.status = stVulnerable
        res.message = "[" & tmp.id & "] " & tmp.info.name & " - PUBLIC OR LISTABLE BUCKET (Code 200)"
        logSuccess(target, res.message)
      else:
        res.status = stFailed
        res.message = "[" & tmp.id & "] not vulnerable (Received code: " & $response.code & ")"
        if cfg.output.verbose: logFail(target, res.message)
  except CatchableError as e:
    res.status = stError
    res.message = "[" & tmp.id & "] Connection error: " & e.msg
    logError(res.message)
  finally:
    client.close()

  return res

# ==================== TABLE DE DISPATCH ====================

let handlers = {
  protoLdap: runLdap,
  protoSmb: runSmb,
  protoKerberos: runKerberos,
  protoHttp: runHttp,
}.toTable

proc runTemplateAsync*(tmp: Template, target: string, cfg: AdConfig): Future[AuditResult] {.async.} =
  let protocol =
    try: parseProtocol(tmp.protocol)
    except ValueError:
      var res = newAuditResult(target, tmp.id, protoHttp, tmp.action)
      res.status = stError
      res.message = "Protocole non supporté : " & tmp.protocol
      logError(res.message)
      return res

  if protocol notin handlers:
    var res = newAuditResult(target, tmp.id, protocol, tmp.action)
    res.status = stError
    res.message = "Aucun handler enregistré pour le protocole : " & $protocol
    logError(res.message)
    return res

  return await handlers[protocol](tmp, target, cfg)
