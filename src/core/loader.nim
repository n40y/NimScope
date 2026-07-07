# src/core/loader.nim

import std/[os, json]

type
  TemplateInfo* = object
    name*: string
    description*: string
    severity*: string

  Template* = object
    id*: string
    protocol*: string
    port*: int
    action*: string
    info*: TemplateInfo

proc discoverTemplates*(dir: string): seq[string] =
  result = @[]
  for file in walkDirRec(dir):
    if file.endsWith(".json"):
      result.add(file)

proc loadTemplate*(path: string): Template =
  let jsonNode = parseFile(path)
  result = to(jsonNode, Template)
