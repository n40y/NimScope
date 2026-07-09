# src/core/config_loader.nim

import std/[json, os]
import ./types

proc getDefaultConfig*(): AdConfig =
  ## Configuration par défaut
  result = AdConfig(
    ad_ports: AdPorts(
      ldap: 389,
      ldaps: 636,
      smb: 445,
      kerberos: 88,
      winrm: 5985
    ),
    ldap_queries: LdapQueries(
      base_dn: "DC=domain,DC=local"
    ),
    output: OutputConfig(
      format: "text",
      path: "reports/",
      verbose: true,
      includeRemediation: true
    ),
    timeouts: TimeoutConfig(
      connection: 3000,
      read: 5000
    )
  )

proc loadAdConfig*(path: string = "config/ad_defaults.json"): AdConfig =
  ## Charge la configuration avec fallback
  try:
    if not fileExists(path):
      echo "[!] Config file not found : " & path
      return getDefaultConfig()
    
    let jsonNode = parseFile(path)
    result = to(jsonNode, AdConfig)
    
  except CatchableError as e:
    echo "[!] Error loading configuration : " & e.msg
    result = getDefaultConfig()
