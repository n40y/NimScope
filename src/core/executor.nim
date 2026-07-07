# src/core/executor.nim

import loader, config_loader
import ../protocols/[ldap, smb]
import logger
import std/[httpclient, asyncdispatch, strutils]

proc runTemplateAsync*(tmp: Template, target: string, cfg: AdConfig) {.async.} =
  case tmp.protocol
  of "ldap":
    if tmp.action == "anonymous-bind":
      let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.ldap
      # Les appels aux protocoles bloquants ou DLL s'exécutent normalement
      let res = tryAnonymousBind(target, port)
      if res == "SUCCESS":
        logSuccess(target, "[" & tmp.id & "] " & tmp.info.name & " - Vulnérabilité confirmée !")
      else:
        logFail(target, "[" & tmp.id & "] non vulnérable (" & res & ")")
  
  of "smb":
    if tmp.action == "check-signing":
      let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.smb
      let res = checkSmbSigning(target, port)
      let osVer = getRemoteOsVersion(target)
      if res == "NOT_REQUIRED":
        logSuccess(target, "[" & tmp.id & "] " & tmp.info.name & " - OS: " & osVer & " - SIGNATURE NON OBLIGATOIRE")
      elif res == "REQUIRED":
        logFail(target, "[" & tmp.id & "] non vulnérable (Signature obligatoire) - OS: " & osVer)
      else:
        logFail(target, "[" & tmp.id & "] impossible de vérifier (" & res & ") - OS: " & osVer)
  
  of "http":
    # Nouveau client HTTP Asynchrone
    let client = newAsyncHttpClient(userAgent = "NimScope/0.1")
    let url = if target.startsWith("http"): 
            target 
          elif target == "169.254.169.254": 
            "http://" & target & "/latest/meta-data/"
          else: 
            "https://" & target & ".s3.amazonaws.com"
    
    try:
      logInfo("Requête HTTP GET asynchrone vers : " & url)
      # 'await' cède la main aux autres templates pendant que le réseau répond
      let response = await client.get(url)
      
      if tmp.action == "check-acl":
        if response.code == Http200:
          logSuccess(target, "[" & tmp.id & "] " & tmp.info.name & " - BUCKET PUBLIC OU LISTABLE (Code 200)")
        else:
          logFail(target, "[" & tmp.id & "] non vulnérable (Code reçu : " & $response.code & ")")
          
    except CatchableError as e:
      logFail(target, "[" & tmp.id & "] Erreur de connexion : " & e.msg)
    finally:
      client.close()
    
  else:
    logError("Protocole non supporté : " & tmp.protocol)