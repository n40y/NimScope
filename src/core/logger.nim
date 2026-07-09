# src/core/logger.nim

import std/[times, terminal]

proc getTimestamp(): string =
  now().format("HH:mm:ss")

proc logInfo*(msg: string) =
  echo "[" & getTimestamp() & "] [*] " & msg

proc logSuccess*(target, msg: string) =
  # Green terminal color code \x1B[32m
  echo "\x1B[32m[" & getTimestamp() & "] [+] " & target & " -> " & msg & "\x1B[0m"

proc logFail*(target, msg: string) =
  # Regular output for non-vulnerable targets
  echo "[" & getTimestamp() & "] [-] " & target & " -> " & msg

proc logError*(msg: string) =
  echo "\x1B[31m[" & getTimestamp() & "] [!] ERROR: " & msg & "\x1B[0m"

proc displayBanner*() =
  let banner = """
█   █ ███ █   █  ████  ███   ███  ████  █████   
██  █░ █░░██ ██░█ ░░░░█ ░░░ █ ░░█ █░░░█ █░░░░░  
█░█ █░░█░░█░█ █░░███░░█░ ░░░█░ ░█░████░░████░░░ 
█░░██░░█░░█░░░█░░ ░░█ █░░   █░░ █░█░░░░ █░░░░   
█░░ █░███░█░░ █░████░░ ███   ███ ░█░░░░░█████░  
 ░░  ░░░░░ ░░  ░░░░░░ ░ ░░░   ░░░ ░░░    ░░░░░  v0.1 
  ░   ░ ░░░ ░   ░ ░░░░   ░░░    ░░░  ░     ░░░░░       """
  stdout.styledWrite(fgMagenta, styleBright, banner, "\n", resetStyle)
  stdout.styledWrite(fgWhite, "  -> Cloud & Active Directory Audit Framework\n", resetStyle)
  echo "---------------------------------------------------------\n"
