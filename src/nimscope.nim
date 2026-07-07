# src/nimscope.nim

import cligen
import std/[asyncdispatch, asyncfutures]
import core/[logger, loader, executor, config_loader]

# --- MODE ACTIVE DIRECTORY ---
proc ad(target: string, template_id: string = "all", silent: bool = false) =
  ## Mode d'audit Active Directory : Lance les vérifications de protocoles et templates AD.
  if not silent:
    displayBanner()

  logInfo("Mode choisi : ACTIVE DIRECTORY")
  logInfo("Cible AD définie : " & target)
  
  let cfg = loadAdConfig()
  let files = discoverTemplates("templates/active_directory")
  logInfo("Nombre de templates AD chargés : " & $files.len)
  echo ""

  var tasks: seq[Future[void]] = @[]

  for f in files:
    let tmp = loadTemplate(f)
    if template_id == "all" or tmp.id == template_id:
      logInfo("Lancement asynchrone du template : " & tmp.info.name & " [" & tmp.id & "]")
      tasks.add(runTemplateAsync(tmp, target, cfg))
  
  if tasks.len > 0:
    waitFor all(tasks)

# --- MODE CLOUD ---
proc cloud(target: string, template_id: string = "all", silent: bool = false) =
  ## Mode d'audit Cloud : Lance les vérifications d'infrastructures Cloud (AWS, Azure, GCP).
  if not silent:
    displayBanner()

  logInfo("Mode choisi : CLOUD")
  logInfo("Endpoint Cloud défini : " & target)
  
  let files = discoverTemplates("templates/cloud")
  let dummyCfg = loadAdConfig()
  logInfo("Nombre de templates Cloud chargés : " & $files.len)
  echo ""

  var tasks: seq[Future[void]] = @[]

  for f in files:
    let tmp = loadTemplate(f)
    if template_id == "all" or tmp.id == template_id:
      logInfo("Lancement asynchrone du template : " & tmp.info.name & " [" & tmp.id & "]")
      tasks.add(runTemplateAsync(tmp, target, dummyCfg))
  
  if tasks.len > 0:
    waitFor all(tasks)

when isMainModule:
  dispatchMulti(
    [ad, help = {
      "target": "IP du contrôleur de domaine ou nom de domaine AD",
      "template_id": "ID du template AD spécifique à lancer (par défaut: all)",
      "silent": "Masquer le banner au démarrage"
    }],
    [cloud, help = {
      "target": "URL de l'API Cloud, endpoint ou nom du bucket à cibler",
      "template_id": "ID du template Cloud spécifique à lancer (par défaut: all)",
      "silent": "Masquer le banner au démarrage"
    }]
  )