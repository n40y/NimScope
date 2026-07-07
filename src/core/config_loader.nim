# src/core/config_loader.nim

import std/json
import loader 

type
  AdPorts* = object
    ldap*: int
    smb*: int
    kerberos*: int

  LdapQueries* = object
    base_dn*: string

  AdConfig* = object
    ad_ports*: AdPorts
    ldap_queries*: LdapQueries

proc loadAdConfig*(path: string = "config/ad_defaults.json"): AdConfig =
  try:
    let jsonNode = parseFile(path)
    result = to(jsonNode, AdConfig)
  except CatchableError as e:
    echo "[!] Error loading global configuration file: " & e.msg
    # Fallback default values
    result = AdConfig(
      ad_ports: AdPorts(ldap: 389, smb: 445, kerberos: 88),
      ldap_queries: LdapQueries(base_dn: "DC=domain,DC=local")
    )
