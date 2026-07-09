# src/core/types.nim
##
## Types centraux de NimScope.
## Objectif de cette révision :
##   - remplacer les strings magiques ("SUCCESS", "ldap", ...) par des enums
##     => erreurs détectées à la compilation plutôt qu'au runtime
##   - rendre `Template` extensible pour Kerberos / énumération LDAP à venir
##     (matchers, actions multiples, options par protocole)
##   - séparer clairement config / résultat / template

import std/[json, times, options, tables, enums]

# ==================== ENUMS ====================

type
  Protocol* = enum
    ## Protocoles supportés. Ajouter ici = seul endroit à toucher pour
    ## que le compilateur te force à gérer le cas partout (executor, etc.)
    protoLdap = "ldap"
    protoSmb = "smb"
    protoKerberos = "kerberos"
    protoNtlm = "ntlm"
    protoHttp = "http"

  AuditStatus* = enum
    stUnknown = "UNKNOWN"
    stSuccess = "SUCCESS"
    stVulnerable = "VULNERABLE"
    stFailed = "FAILED"
    stError = "ERROR"
    stPortClosed = "PORT_CLOSED"

  Severity* = enum
    sevInfo = "INFO"
    sevLow = "LOW"
    sevMedium = "MEDIUM"
    sevHigh = "HIGH"
    sevCritical = "CRITICAL"

# Helpers de (dé)sérialisation string <-> enum, car les JSON de templates
# et l'AdConfig existant utilisent des strings en minuscule/majuscule.
proc parseProtocol*(s: string): Protocol =
  try:
    result = parseEnum[Protocol](s.toLowerAscii())
  except ValueError:
    raise newException(ValueError, "Protocole inconnu dans le template : " & s)

proc parseSeverity*(s: string): Severity =
  try:
    result = parseEnum[Severity](s.toUpperAscii())
  except ValueError:
    result = sevInfo

# ==================== CONFIGURATION ====================

type
  AdPorts* = object
    ldap*: int
    ldaps*: int
    smb*: int
    kerberos*: int
    winrm*: int

  LdapQueries* = object
    base_dn*: string

  OutputConfig* = object
    format*: string
    path*: string
    verbose*: bool
    includeRemediation*: bool

  TimeoutConfig* = object
    connection*: int
    read*: int

  AdConfig* = object
    ad_ports*: AdPorts
    ldap_queries*: LdapQueries
    output*: OutputConfig
    timeouts*: TimeoutConfig

# ==================== RÉSULTATS ====================

type
  AuditResult* = object
    target*: string
    templateId*: string
    protocol*: Protocol
    action*: string
    status*: AuditStatus
    message*: string
    details*: JsonNode
    osVersion*: string
    timestamp*: string
    severity*: Severity

proc newAuditResult*(target, templateId: string, protocol: Protocol, action: string): AuditResult =
  AuditResult(
    target: target,
    templateId: templateId,
    protocol: protocol,
    action: action,
    timestamp: now().format("yyyy-MM-dd HH:mm:ss"),
    status: stUnknown,
    severity: sevInfo,
    details: newJObject()
  )

# ==================== TEMPLATE ====================

type
  TemplateInfo* = object
    name*: string
    description*: string
    severity*: string       # brut, converti via parseSeverity() au chargement
    author*: string

  ## `matchers` et `options` sont volontairement génériques (Table[string, string])
  ## pour ne pas avoir à modifier ce type à chaque nouvelle action Kerberos/LDAP.
  ## Un template "ldap-enum-spns" ou "kerberos-asrep-roast" peut ainsi porter
  ## des paramètres arbitraires sans casser le schéma JSON existant.
  Template* = object
    id*: string
    protocol*: string        # brut, converti via parseProtocol() au chargement
    port*: int
    action*: string
    info*: TemplateInfo
    matchers*: Option[Table[string, string]]
    options*: Option[Table[string, string]]

# ==================== DISPATCH PAR PROTOCOLE ====================

type
  ## Signature commune que chaque handler de protocole doit respecter.
  ## Permet à executor.nim de remplacer son `case` géant par une table
  ## de dispatch : ajouter Kerberos = ajouter une entrée, pas modifier
  ## un bloc de 100 lignes.
  ProtocolHandler* = proc(tmp: Template, target: string, cfg: AdConfig): AuditResult {.gcsafe.}
