# src/core/logger.nim
import std/[times, terminal, os]
import ./types

var colorEnabled = true  ## contrôlé par --no-color (CLI) ou variable d'env NO_COLOR

proc initLogger*(noColor: bool = false) =
  ## À appeler une fois au démarrage (depuis nimscope.nim), une fois les
  ## flags CLI parsés.
  colorEnabled = not noColor and existsEnv("NO_COLOR") == false and stdout.isatty()

proc getTimestamp(): string =
  now().format("HH:mm:ss")

proc styled(color: ForegroundColor, bright: bool, prefix: string, msg: string) =
  if colorEnabled:
    let style = if bright: {styleBright} else: {}
    stdout.styledWrite(color, style, "[" & getTimestamp() & "] " & prefix & " " & msg, resetStyle)
    stdout.write("\n")
  else:
    echo "[" & getTimestamp() & "] " & prefix & " " & msg

proc logInfo*(msg: string) =
  styled(fgCyan, false, "[*]", msg)

proc logSuccess*(target, msg: string) =
  styled(fgGreen, true, "[+]", target & " -> " & msg)

proc logWarning*(target, msg: string) =
  styled(fgYellow, true, "[~]", target & " -> " & msg)

proc logFail*(target, msg: string) =
  # Résultat neutre (ex: check passé, rien trouvé) -> pas de couleur vive,
  # pour que les vrais résultats positifs (vert/rouge) ressortent visuellement.
  echo "[" & getTimestamp() & "] [-] " & target & " -> " & msg

proc logError*(msg: string) =
  styled(fgRed, true, "[!] ERROR:", msg)

proc logByStatus*(target: string, status: AuditStatus, msg: string) =
  ## Route vers la bonne couleur selon le statut de l'audit -> réutilisable
  ## depuis reporter.nim pour que le résumé console soit cohérent avec les
  ## logs pendant l'exécution.
  case status
  of stVulnerable: logWarning(target, msg)  # jaune : attire l'oeil sans "alarme rouge" prématurée
  of stSuccess: logSuccess(target, msg)
  of stError: logError(target & " -> " & msg)
  else: logFail(target, msg)

proc displayBanner*() =
  let banner = """
█   █ ███ █   █  ████  ███   ███  ████  █████   
██  █░ █░░██ ██░█ ░░░░█ ░░░ █ ░░█ █░░░█ █░░░░░  
█░█ █░░█░░█░█ █░░███░░█░ ░░░█░ ░█░████░░████░░░ 
█░░██░░█░░█░░░█░░ ░░█ █░░   █░░ █░█░░░░ █░░░░   
█░░ █░███░█░░ █░████░░ ███   ███ ░█░░░░░█████░  
 ░░  ░░░░░ ░░  ░░░░░░ ░ ░░░   ░░░ ░░░    ░░░░░  v0.1 
  ░   ░ ░░░ ░   ░ ░░░░   ░░░    ░░░  ░     ░░░░░       """
  if colorEnabled:
    stdout.styledWrite(fgMagenta, styleBright, banner, "\n", resetStyle)
    stdout.styledWrite(fgWhite, "  -> Cloud & Active Directory Audit Framework\n", resetStyle)
  else:
    echo banner
    echo "  -> Cloud & Active Directory Audit Framework"
  echo "---------------------------------------------------------\n"

# Rend colorEnabled accessible en lecture ailleurs
proc colorEnabledCheck*(): bool = colorEnabled
