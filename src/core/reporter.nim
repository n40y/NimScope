# src/core/reporter.nim

import std/[json, os, times, strutils]
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

proc generateReport*(results: seq[AuditResult], target: string) =
  saveJsonReport(results, target)
  printConsoleSummary(results)
