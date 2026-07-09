# src/core/loader.nim

import std/[os, json, strutils]
import ./types # Importation des types centralisés

proc discoverTemplates*(dir: string): seq[string] =
  result = @[]
  for file in walkDirRec(dir):
    if file.endsWith(".json"):
      result.add(file)

proc loadTemplate*(path: string): Template =
  let jsonNode = parseFile(path)
  result = to(jsonNode, Template)
