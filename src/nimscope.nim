# src/nimscope.nim

import cligen
import std/[asyncdispatch, asyncfutures]
import core/[logger, loader, executor, config_loader]

proc displayBanner() =
  let banner = """
█   █ ███ █   █  ████  ███   ███  ████  █████   
██  █░ █░░██ ██░█ ░░░░█ ░░░ █ ░░█ █░░░█ █░░░░░  
█░█ █░░█░░█░█ █░░███░░█░ ░░░█░ ░█░████░░████░░░ 
█░░██░░█░░█░░░█░░ ░░█ █░░   █░░ █░█░░░░ █░░░░   
█░░ █░███░█░░ █░████░░ ███   ███ ░█░░░░░█████░  
 ░░  ░░░░░ ░░  ░░░░░░ ░ ░░░   ░░░ ░░░    ░░░░░  
  ░   ░ ░░░ ░   ░ ░░░   ░░░   ░░░  ░     ░░░░░  v0.1
  -> Cloud & Active Directory Audit Framework
---------------------------------------------------------"""
  echo banner

proc ad(target: string, template_id: string = "all", silent: bool = false) =
  ## Active Directory Audit Mode: Run protocol checks and AD templates.
  if not silent:
    displayBanner()

  logInfo("Selected mode: ACTIVE DIRECTORY")
  logInfo("AD Target defined: " & target)
  
  let cfg = loadAdConfig()
  let files = discoverTemplates("templates/active_directory")
  logInfo("Number of loaded AD templates: " & $files.len)
  echo ""

  var tasks: seq[Future[void]] = @[]

  for f in files:
    let tmp = loadTemplate(f)
    if template_id == "all" or tmp.id == template_id:
      logInfo("Asynchronously spawning template: " & tmp.info.name & " [" & tmp.id & "]")
      tasks.add(runTemplateAsync(tmp, target, cfg))
  
  if tasks.len > 0:
    waitFor all(tasks)

proc cloud(target: string, template_id: string = "all", silent: bool = false) =
  ## Cloud Audit Mode: Run cloud infrastructure checks (AWS, Azure, GCP).
  if not silent:
    displayBanner()

  logInfo("Selected mode: CLOUD")
  logInfo("Cloud Endpoint defined: " & target)
  
  let files = discoverTemplates("templates/cloud")
  let dummyCfg = loadAdConfig()
  logInfo("Number of loaded Cloud templates: " & $files.len)
  echo ""

  var tasks: seq[Future[void]] = @[]

  for f in files:
    let tmp = loadTemplate(f)
    if template_id == "all" or tmp.id == template_id:
      logInfo("Asynchronously spawning template: " & tmp.info.name & " [" & tmp.id & "]")
      tasks.add(runTemplateAsync(tmp, target, dummyCfg))
  
  if tasks.len > 0:
    waitFor all(tasks)

# --------------------------------------------------
when isMainModule:
  dispatchMulti(
    [ad, help = {
      "target": "IP or domain name of the Active Directory Domain Controller",
      "template_id": "Specific AD template ID to run (default: all)",
      "silent": "Hide the ASCII banner on startup"
    }],
    [cloud, help = {
      "target": "Cloud API URL, endpoint, or bucket name to target",
      "template_id": "Specific Cloud template ID to run (default: all)",
      "silent": "Hide the ASCII banner on startup"
    }]
  )
