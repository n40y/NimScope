# src/nimscope.nim

import cligen
import std/[asyncdispatch, asyncfutures]
import core/[logger, loader, executor, config_loader, types, reporter]

proc ad(target: string, template_id: string = "all", silent: bool = false,
        format: string = "text", verbose: bool = false, noColor: bool = false) =
  ## Active Directory Audit Mode: Run protocol checks and AD templates.
  initLogger(noColor)
  if not silent:
    displayBanner()

  logInfo("Selected mode: ACTIVE DIRECTORY")
  logInfo("AD Target defined: " & target)

  var cfg = loadAdConfig()

  if format != "text": cfg.output.format = format
  if verbose: cfg.output.verbose = true

  let files = discoverTemplates("templates/active_directory")
  if cfg.output.verbose:
    logInfo("Number of loaded AD templates: " & $files.len)
  echo ""

  var tasks: seq[Future[AuditResult]] = @[]

  for f in files:
    let tmp = loadTemplate(f)
    if template_id == "all" or tmp.id == template_id:
      if cfg.output.verbose:
        logInfo("Asynchronously spawning template: " & tmp.info.name & " [" & tmp.id & "]")
      tasks.add(runTemplateAsync(tmp, target, cfg))

  if tasks.len > 0:
    let results = waitFor all(tasks)

    if cfg.output.format == "json" or cfg.output.format == "all":
      saveJsonReport(results, target)

    printResultsTable(results)
    printConsoleSummary(results)

proc cloud(target: string, template_id: string = "all", silent: bool = false,
           format: string = "text", verbose: bool = false, noColor: bool = false) =
  ## Cloud Audit Mode: Run cloud infrastructure checks (AWS, Azure, GCP).
  initLogger(noColor)
  if not silent:
    displayBanner()

  logInfo("Selected mode: CLOUD")
  logInfo("Cloud Endpoint defined: " & target)

  var cfg = loadAdConfig()

  if format != "text": cfg.output.format = format
  if verbose: cfg.output.verbose = true

  let files = discoverTemplates("templates/cloud")
  if cfg.output.verbose:
    logInfo("Number of loaded Cloud templates: " & $files.len)
  echo ""

  var tasks: seq[Future[AuditResult]] = @[]

  for f in files:
    let tmp = loadTemplate(f)
    if template_id == "all" or tmp.id == template_id:
      if cfg.output.verbose:
        logInfo("Asynchronously spawning template: " & tmp.info.name & " [" & tmp.id & "]")
      tasks.add(runTemplateAsync(tmp, target, cfg))

  if tasks.len > 0:
    let results = waitFor all(tasks)

    if cfg.output.format == "json" or cfg.output.format == "all":
      saveJsonReport(results, target)

    printResultsTable(results)
    printConsoleSummary(results)

# --------------------------------------------------
when isMainModule:
  dispatchMulti(
    [ad, help = {
      "target": "IP or domain name of the Active Directory Domain Controller",
      "template_id": "Specific AD template ID to run (default: all)",
      "silent": "Hide the ASCII banner on startup",
      "format": "Output format: text, json, all (default: text)",
      "verbose": "Enable verbose logging",
      "noColor": "Disable colored output (useful for redirecting to a file or CI)"
    }],
    [cloud, help = {
      "target": "Cloud API URL, endpoint, or bucket name to target",
      "template_id": "Specific Cloud template ID to run (default: all)",
      "silent": "Hide the ASCII banner on startup",
      "format": "Output format: text, json, all (default: text)",
      "verbose": "Enable verbose logging",
      "noColor": "Disable colored output (useful for redirecting to a file or CI)"
    }]
  )
