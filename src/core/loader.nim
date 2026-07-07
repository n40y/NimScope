# src/core/loader.nim

import std/[os, strutils, json]

type
  TemplateInfo* = object
    name*: string
    description*: string
    severity*: string

  Template* = object
    id*: string
    info*: TemplateInfo
    protocol*: string
    action*: string
    port*: int

proc loadTemplate*(path: string): Template =
  let node = parseFile(path)
  # On désérialise le JSON directement dans notre objet Nim
  return node.to(Template)

proc discoverTemplates*(baseDir: string = "templates"): seq[string] =
  result = @[]
  if not dirExists(baseDir):
    createDir(baseDir)
    return
  
  # On parcourt récursivement pour trouver tous les fichiers JSON
  for path in walkDirRec(baseDir):
    if path.endsWith(".json"):
      result.add(path)