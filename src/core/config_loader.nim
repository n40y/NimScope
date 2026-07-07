# src/core/config_loader.nim

import std/[os, json]

type
  AdPorts* = object
    ldap*: int
    ldaps*: int
    smb*: int
    kerberos*: int
    winrm*: int

  DefaultQueries* = object
    naming_contexts*: string

  AdConfig* = object
    ad_ports*: AdPorts
    default_queries*: DefaultQueries

proc loadAdConfig*(path: string = "config/ad_defaults.json"): AdConfig =
  if not fileExists(path):
    # Si le fichier de config n'existe pas, on renvoie des valeurs hardcodées de secours
    return AdConfig(
      ad_ports: AdPorts(ldap: 389, ldaps: 636, smb: 445, kerberos: 88, winrm: 5985),
      default_queries: DefaultQueries(naming_contexts: "(objectClass=*)")
    )
  
  let node = parseFile(path)
  return node.to(AdConfig)