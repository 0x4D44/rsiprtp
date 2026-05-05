# Overnight fuzz wrapper — see wrk_journals/2026.05.04 - JRN - overnight-fuzz-soak.md
# and wrk_journals/2026.05.05 - JRN - per-header fuzz targets implementation.md
# (Stage 6) for the multi-target rotation design.
#
# Loops `cargo +nightly fuzz run <target>` over a round-robin rotation of
# targets until the cumulative fuzz budget (default 8h) is exhausted. Each
# slice runs one target for at most $SliceSeconds (default 30 min) or the
# remaining budget, whichever is smaller. Pauses on crash until a RESUME
# file is touched by the supervisor; wall-clock pause time does NOT count
# against the budget.
#
# stdout grammar (one event per line, all space-separated):
#   START     budget=<sec> deadline=<utc-iso> targets=<csv>
#   HEARTBEAT run=<n> target=<name> elapsed=<sec> remaining=<sec> [stat=[...]]
#   CLEAN     run=<n> target=<name> ran=<sec>
#   CRASH     run=<n> target=<name> exit=<code> queue=<dir>
#   RESUME    run=<n> target=<name> waited=<sec>
#   DONE      total_runs=<n> total_crashes=<n> fuzz_time=<sec>

param(
  [int]$BudgetSeconds = 28800,    # 8h
  [int]$HeartbeatSeconds = 300,   # 5 min
  [int]$SliceSeconds = 1800,      # 30 min per target slice
  [int]$RssLimitMb = 2048,
  [string[]]$Targets = @(
    "sip_message_roundtrip",
    "sip_via_typed",
    "sip_contact",
    "sip_name_addr",
    "sip_cseq",
    "sdp_session_roundtrip"
  )
)

$ErrorActionPreference = "Stop"
$RepoRoot   = $PSScriptRoot
$LogsDir    = Join-Path $RepoRoot "wrk_journals\fuzz_logs"
$TriageDir  = Join-Path $RepoRoot "wrk_journals\fuzz_triage"

New-Item -ItemType Directory -Path $LogsDir   -Force | Out-Null
New-Item -ItemType Directory -Path $TriageDir -Force | Out-Null

# Per-target working-directory map. The cwd must be the parent of the
# `fuzz/` crate that defines that target's bin stanza, since
# `cargo +nightly fuzz run` walks up from cwd to find it.
$TargetCwd = @{
  "sip_message_roundtrip"  = $RepoRoot
  "sip_via_typed"          = $RepoRoot
  "sip_contact"            = $RepoRoot
  "sip_name_addr"          = $RepoRoot
  "sip_cseq"               = $RepoRoot
  "sdp_session_roundtrip"  = $RepoRoot
}

# Verify every target in the rotation has a cwd mapping. Fail loud if not.
foreach ($t in $Targets) {
  if (-not $TargetCwd.ContainsKey($t)) {
    throw "No working-directory mapping for target '$t'. Update `$TargetCwd in fuzz_overnight.ps1."
  }
}

# Pre-create per-target artifact directories so libFuzzer has somewhere to
# drop crash artifacts. Layout is <cwd>/fuzz/artifacts/<target>.
foreach ($t in $Targets) {
  $cwd = $TargetCwd[$t]
  $art = Join-Path $cwd "fuzz\artifacts\$t"
  New-Item -ItemType Directory -Path $art -Force | Out-Null
}

# MSVC ASAN dll on PATH (Windows-MSVC requirement for cargo-fuzz)
$AsanDir = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
if ($env:PATH -notlike "*$AsanDir*") {
  $env:PATH = "$AsanDir;" + $env:PATH
}

function EmitLine([string]$line) {
  Write-Host $line
  [Console]::Out.Flush()
}

$StartUtc       = [DateTime]::UtcNow
$DeadlineUtc    = $StartUtc.AddSeconds($BudgetSeconds)
$RunIndex       = 0
$CrashCount     = 0
$FuzzTimeSpent  = 0
$TargetsCsv     = ($Targets -join ",")

EmitLine ("START budget={0} deadline={1:yyyy-MM-ddTHH:mm:ssZ} targets={2}" -f $BudgetSeconds, $DeadlineUtc, $TargetsCsv)

while ($true) {
  $remaining = [int][Math]::Floor(($DeadlineUtc - [DateTime]::UtcNow).TotalSeconds)
  if ($remaining -le 60) {
    break
  }

  $RunIndex += 1
  $target   = $Targets[($RunIndex - 1) % $Targets.Count]
  $cwd      = $TargetCwd[$target]
  $ArtDir   = Join-Path $cwd "fuzz\artifacts\$target"

  $runId      = "run_{0:D3}_{1}" -f $RunIndex, $target
  $logPath    = Join-Path $LogsDir "$runId.log"
  $errPath    = Join-Path $LogsDir "$runId.err"
  $runStartUtc = [DateTime]::UtcNow

  # Bound slice by remaining budget so the last visit doesn't overshoot.
  $sliceCap = [Math]::Min($SliceSeconds, $remaining)

  # Spawn cargo-fuzz as a child so we can heartbeat alongside it.
  # libFuzzer exits non-zero on crash; we treat that as a triage event.
  $cargoArgs = @(
    "+nightly", "fuzz", "run", $target, "--",
    "-max_total_time=$sliceCap",
    "-timeout=10",
    "-rss_limit_mb=$RssLimitMb"
  )

  Set-Content -Path $logPath -Value "" -NoNewline -Encoding utf8
  Set-Content -Path $errPath -Value "" -NoNewline -Encoding utf8

  $proc = Start-Process -FilePath "cargo" -ArgumentList $cargoArgs `
    -WorkingDirectory $cwd `
    -RedirectStandardOutput $logPath `
    -RedirectStandardError  $errPath `
    -NoNewWindow -PassThru

  $lastBeat = [DateTime]::UtcNow
  while (-not $proc.HasExited) {
    Start-Sleep -Milliseconds 1000
    $now = [DateTime]::UtcNow
    if (($now - $lastBeat).TotalSeconds -ge $HeartbeatSeconds) {
      $elapsedThisRun = [int]($now - $runStartUtc).TotalSeconds
      $remainingNow   = [int][Math]::Floor(($DeadlineUtc - $now).TotalSeconds)
      # Sample the most recent libfuzzer status line for the heartbeat
      $lastStat = ""
      if (Test-Path $errPath) {
        $tail = Get-Content $errPath -Tail 5 -ErrorAction SilentlyContinue
        $statLine = $tail | Where-Object { $_ -match "^#\d+\s" } | Select-Object -Last 1
        if ($statLine) { $lastStat = ($statLine -replace "\s+", " ").Trim() }
      }
      if ($lastStat) {
        EmitLine ("HEARTBEAT run={0} target={1} elapsed={2} remaining={3} stat=[{4}]" -f $RunIndex, $target, $elapsedThisRun, $remainingNow, $lastStat)
      } else {
        EmitLine ("HEARTBEAT run={0} target={1} elapsed={2} remaining={3}" -f $RunIndex, $target, $elapsedThisRun, $remainingNow)
      }
      $lastBeat = $now
    }
  }

  # Append err into log so triage has one file to read
  if ((Test-Path $errPath) -and (Get-Item $errPath).Length -gt 0) {
    Add-Content -Path $logPath -Value "`n--- STDERR ---`n" -Encoding utf8
    Get-Content $errPath | Add-Content -Path $logPath -Encoding utf8
  }

  $exitCode      = $proc.ExitCode
  $runEndUtc     = [DateTime]::UtcNow
  $runRanSeconds = [int]($runEndUtc - $runStartUtc).TotalSeconds
  $FuzzTimeSpent += $runRanSeconds

  if ($exitCode -eq 0) {
    EmitLine ("CLEAN run={0} target={1} ran={2}" -f $RunIndex, $target, $runRanSeconds)
    continue
  }

  # Non-zero — treat as crash. Move artifacts + log into a triage slot,
  # then wait for supervisor to touch RESUME before continuing.
  $CrashCount += 1
  $slot = "crash_{0:D3}_{1}" -f $RunIndex, $target
  $slotPath = Join-Path $TriageDir $slot
  New-Item -ItemType Directory -Path $slotPath -Force | Out-Null

  Copy-Item $logPath (Join-Path $slotPath "fuzz.log") -Force

  # Capture any artifact files written by libFuzzer (may be empty on
  # Windows __fastfail per prior journal — log is the source of truth).
  if (Test-Path $ArtDir) {
    Get-ChildItem $ArtDir -File | ForEach-Object {
      Copy-Item $_.FullName (Join-Path $slotPath $_.Name) -Force
      Remove-Item $_.FullName -Force
    }
  }

  EmitLine ("CRASH run={0} target={1} exit={2} queue={3}" -f $RunIndex, $target, $exitCode, $slot)

  # Wait for supervisor to touch RESUME inside the slot. Whole rotation
  # pauses — operational triage discipline. Reviewer attention is the
  # scarce resource; a real crash should be reviewed before more fuzzing
  # on any target. (The 5 targets have separate corpora, so cross-target
  # mutator contamination is not the rationale.)
  $waitStart = [DateTime]::UtcNow
  $resumePath = Join-Path $slotPath "RESUME"
  while (-not (Test-Path $resumePath)) {
    Start-Sleep -Seconds 5
  }
  $waited = [int]([DateTime]::UtcNow - $waitStart).TotalSeconds
  EmitLine ("RESUME run={0} target={1} waited={2}" -f $RunIndex, $target, $waited)
}

EmitLine ("DONE total_runs={0} total_crashes={1} fuzz_time={2}" -f $RunIndex, $CrashCount, $FuzzTimeSpent)
