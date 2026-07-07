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
      let res = tryAnonymousBind(target, port)
      if res == "SUCCESS":
        logSuccess(target, "[" & tmp.id & "] " & tmp.info.name & " - VULNERABILITY CONFIRMED!")
      else:
        logFail(target, "[" & tmp.id & "] not vulnerable (" & res & ")")
  
  of "smb":
    if tmp.action == "check-signing":
      let port = if tmp.port != 0: tmp.port else: cfg.ad_ports.smb
      let res = checkSmbSigning(target, port)
      let osVer = getRemoteOsVersion(target)
      if res == "NOT_REQUIRED":
        logSuccess(target, "[" & tmp.id & "] " & tmp.info.name & " - OS: " & osVer & " - SIGNING NOT REQUIRED")
      elif res == "REQUIRED":
        logFail(target, "[" & tmp.id & "] not vulnerable (Signing required) - OS: " & osVer)
      else:
        logFail(target, "[" & tmp.id & "] unable to verify (" & res & ") - OS: " & osVer)
  
  of "http":
    let client = newAsyncHttpClient(userAgent = "NimScope/0.1")
    let url = if target.startsWith("http"): 
                target 
              elif target == "169.254.169.254": 
                "http://" & target & "/latest/meta-data/"
              else: 
                "https://" & target & ".s3.amazonaws.com"
    
    try:
      logInfo("Asynchronous HTTP GET request to: " & url)
      let response = await client.get(url)
      
      if tmp.action == "check-acl":
        if response.code == Http200:
          logSuccess(target, "[" & tmp.id & "] " & tmp.info.name & " - PUBLIC OR LISTABLE BUCKET (Code 200)")
        else:
          logFail(target, "[" & tmp.id & "] not vulnerable (Received code: " & $response.code & ")")
          
    except CatchableError as e:
      logFail(target, "[" & tmp.id & "] Connection error: " & e.msg)
    finally:
      client.close()
    
  else:
    logError("Unsupported protocol: " & tmp.protocol)
