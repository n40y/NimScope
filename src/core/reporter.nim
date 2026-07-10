# src/core/reporter.nim
import std/[json, os, times, strutils, algorithm, terminal]
import ./types, ./logger

proc saveJsonReport*(results: seq[AuditResult], target: string) =
  ## Sauvegarde les résultats au format JSON
  let reportDir = "reports"
  if not dirExists(reportDir):
    createDir(reportDir)

  let filename = reportDir / ("audit_" & target & "_" & now().format("yyyyMMdd'_'HHmm") & ".json")

  var report = %*{
    "target": target,
    "timestamp": now().format("yyyy-MM-dd HH:mm:ss"),
    "total_checks": results.len,
    "results": results
  }

  writeFile(filename, report.pretty())
  logInfo("JSON report saved : " & filename)

proc printConsoleSummary*(results: seq[AuditResult]) =
  ## Affiche un résumé en console
  var successCount = 0
  var vulnerableCount = 0

  for r in results:
    if r.status == stSuccess or r.status == stVulnerable:
      successCount += 1
      if r.status == stVulnerable:
        vulnerableCount += 1

  echo "\n" & "=".repeat(60)
  logInfo("=== AUDIT COMPLETED ===")
  echo "Target            : " & (if results.len > 0: results[0].target else: "N/A")
  echo "Checks performed : " & $results.len
  echo "Success / Vuln    : " & $successCount & " (" & $vulnerableCount & " vulnerabilities)"
  echo "=".repeat(60)

proc severityColor(sev: Severity): ForegroundColor =
  case sev
  of sevCritical: fgRed
  of sevHigh: fgRed
  of sevMedium: fgYellow
  of sevLow: fgCyan
  of sevInfo: fgWhite

proc printResultsTable*(results: seq[AuditResult]) =
  ## Tableau récapitulatif : sévérité descendante d'abord (les problèmes
  ## en haut), puis alphabétique par template pour la stabilité de l'ordre.
  var sorted = results
  sorted.sort(proc(a, b: AuditResult): int =
    let sevOrder = [sevCritical, sevHigh, sevMedium, sevLow, sevInfo]
    let ia = sevOrder.find(a.severity)
    let ib = sevOrder.find(b.severity)
    if ia != ib: return ia - ib
    return cmp(a.templateId, b.templateId)
  )

  echo "\n" & "─".repeat(78)
  echo "SUMMARY"
  echo "─".repeat(78)

  for r in sorted:
    let icon = case r.status
      of stVulnerable: "!"
      of stSuccess: "+"
      of stError: "x"
      else: "-"

    let templateCol = r.templateId.alignLeft(32)
    let sevCol = ($r.severity).alignLeft(9)

    if colorEnabledCheck():
      stdout.styledWrite(severityColor(r.severity), styleBright,
        "[" & icon & "] ", resetStyle,
        templateCol, " ", sevCol, " ", r.message, "\n")
    else:
      echo "[" & icon & "] " & templateCol & " " & sevCol & " " & r.message

  echo "─".repeat(78)

proc generateReport*(results: seq[AuditResult], target: string) =
  saveJsonReport(results, target)
  printResultsTable(results)
  printConsoleSummary(results)
