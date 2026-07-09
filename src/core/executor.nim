# src/core/executor.nim
##
## Révision : le `case tmp.protocol` unique devient une table de dispatch
## async, indexée par Protocol. Ajouter Kerberos ou une nouvelle action
## LDAP = écrire un proc `runXxx` + l'enregistrer dans `handlers`,
## sans toucher au reste du fichier.

import std/[asyncdispatch, strutils, json, tables, httpclient]
import ./types, ./logger
import ../protocols/ldap
import ../protocols/smb
# import ../protocols/kerberos  # à activer une fois le module réécrit en pur Nim

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
    let bindStatus = toStatus(tryAnonymousBind(target, port))
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

    let data = queryLdap(target, port, baseDn, filter, attrs)

    if data.len > 0:
      res.status = stVulnerable
      res.details = data
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

  if tmp.action == "check-signing":
    let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.smb
    let signingStatus = checkSmbSigning(target, port)   # string brut ("NOT_REQUIRED", "REQUIRED", ...)
    let osVer = getRemoteOsVersion(target)
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
      res.message = "[" & tmp.id & "] unable to verify (" & signingStatus & ") - OS: " & osVer
      if cfg.output.verbose: logFail(target, res.message)
  else:
    res.status = stError
    res.message = "Action SMB inconnue : " & tmp.action
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
  protoHttp: runHttp,
  # protoKerberos: runKerberos,  # à ajouter quand le module sera portable
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
