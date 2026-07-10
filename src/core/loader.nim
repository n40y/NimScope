# src/core/loader.nim

import std/[os, json, strutils]
import ./types
import ./logger

proc discoverTemplates*(dir: string): seq[string] =
  result = @[]
  
  var templateDir = dir
  if not dirExists(templateDir):
    templateDir = "../" & dir
  
  if not dirExists(templateDir):
    logError("Templates directory not found: " & templateDir)
    return
  
  for path in walkDirRec(templateDir):
    if path.endsWith(".json"):
      result.add(path)
  
  logInfo("Found " & $result.len & " templates in " & templateDir)
proc loadTemplate*(path: string): Template =
  let jsonNode = parseFile(path)
  result = to(jsonNode, Template)
