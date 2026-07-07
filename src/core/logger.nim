import std/[terminal, times]

# Génère un timestamp propre : [17:45:12]
proc getTimestamp(): string =
  return "[" & now().format("HH:mm:ss") & "] "

# Info générique (Bleu / Cyan)
proc logInfo*(msg: string) =
  stdout.styledWrite(fgCyan, getTimestamp(), fgBlue, "[*] ", resetStyle, msg, "\n")

# Alerte / Vulnérabilité trouvée (Vert flashy + tag Pwned)
proc logSuccess*(target: string, msg: string) =
  stdout.styledWrite(fgCyan, getTimestamp(), fgGreen, "[+] ", bgGreen, fgBlack, " PWNED ", resetStyle, " ", fgGreen, target, resetStyle, " -> ", msg, "\n")

# Échec / Non vulnérable ou accès refusé (Blanc/Gris standard)
proc logFail*(target: string, msg: string) =
  stdout.styledWrite(fgCyan, getTimestamp(), fgRed, "[-] ", resetStyle, fgWhite, target, " -> ", msg, "\n")

# Erreur critique du script (Rouge vif)
proc logError*(msg: string) =
  stderr.styledWrite(fgRed, styleBright, "[!] ERREUR: ", resetStyle, msg, "\n")

# Joli Banner de démarrage
proc displayBanner*() =
  let banner = """
█   █ ███ █   █  ████  ███   ███  ████  █████   
██  █░ █░░██ ██░█ ░░░░█ ░░░ █ ░░█ █░░░█ █░░░░░  
█░█ █░░█░░█░█ █░░███░░█░ ░░░█░ ░█░████░░████░░░ 
█░░██░░█░░█░░░█░░ ░░█ █░░   █░░ █░█░░░░ █░░░░   
█░░ █░███░█░░ █░████░░ ███   ███ ░█░░░░░█████░  
 ░░  ░░░░░ ░░  ░░░░░░ ░ ░░░   ░░░ ░░░    ░░░░░  v0.1 
  ░   ░ ░░░ ░   ░ ░░░░   ░░░   ░░░  ░     ░░░░░       """
  stdout.styledWrite(fgMagenta, styleBright, banner, "\n", resetStyle)
  stdout.styledWrite(fgWhite, "  -> Framework d'audit Cloud & Active Directory\n", resetStyle) # Modifié ici !
  echo "---------------------------------------------------------\n"