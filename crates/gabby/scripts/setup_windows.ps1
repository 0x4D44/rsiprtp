$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$GabbyDir = Split-Path -Parent $ScriptDir

Write-Host "=== Gabby Windows Vosk Setup ==="
Write-Host "Working directory: $GabbyDir"

$ModelName = "vosk-model-small-en-us-0.15"
$ModelDir = Join-Path $GabbyDir "models"
$ModelPath = Join-Path $ModelDir $ModelName
$ModelZip = Join-Path $env:TEMP "vosk-model.zip"

$VoskVersion = "0.3.45"
$VoskRoot = Join-Path $GabbyDir "vendor\\vosk"
$VoskZip = Join-Path $env:TEMP "vosk-win64-$VoskVersion.zip"
$VoskUrl = "https://github.com/alphacep/vosk-api/releases/download/v$VoskVersion/vosk-win64-$VoskVersion.zip"

New-Item -ItemType Directory -Path $ModelDir -Force | Out-Null
New-Item -ItemType Directory -Path $VoskRoot -Force | Out-Null

if (-not (Test-Path $ModelPath)) {
    Write-Host ""
    Write-Host "Downloading Vosk model ($ModelName)..."
    Invoke-WebRequest -Uri "https://alphacephei.com/vosk/models/$ModelName.zip" -OutFile $ModelZip
    Write-Host "Extracting Vosk model..."
    Expand-Archive -Path $ModelZip -DestinationPath $ModelDir -Force
    Remove-Item $ModelZip -Force
    Write-Host "Vosk model installed to: $ModelPath"
} else {
    Write-Host "Vosk model already installed at: $ModelPath"
}

$ExistingLib = Get-ChildItem -Path $VoskRoot -Recurse -Filter "libvosk.lib" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ExistingLib) {
    Write-Host ""
    Write-Host "Downloading Vosk library (v$VoskVersion)..."
    Invoke-WebRequest -Uri $VoskUrl -OutFile $VoskZip
    Write-Host "Extracting Vosk library..."
    Expand-Archive -Path $VoskZip -DestinationPath $VoskRoot -Force
    Remove-Item $VoskZip -Force
}

$VoskLib = Get-ChildItem -Path $VoskRoot -Recurse -Filter "libvosk.lib" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $VoskLib) {
    throw "libvosk.lib not found under $VoskRoot"
}

$VoskLibDir = $VoskLib.DirectoryName
[Environment]::SetEnvironmentVariable("VOSK_LIB_DIR", $VoskLibDir, "User")
$env:VOSK_LIB_DIR = $VoskLibDir
Write-Host "VOSK_LIB_DIR set to: $VoskLibDir"

$VoskDll = Get-ChildItem -Path $VoskLibDir -Filter "vosk.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $VoskDll) {
    $VoskDll = Get-ChildItem -Path $VoskLibDir -Filter "libvosk.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $VoskDll) {
    $VoskDll = Get-ChildItem -Path $VoskRoot -Recurse -Filter "vosk.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $VoskDll) {
    $VoskDll = Get-ChildItem -Path $VoskRoot -Recurse -Filter "libvosk.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
}

if ($VoskDll) {
    $VoskBinDir = $VoskDll.DirectoryName
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $UserPath) {
        $UserPath = ""
    }

    $PathParts = $UserPath -split ";" | Where-Object { $_ -ne "" }
    if ($PathParts -notcontains $VoskBinDir) {
        $NewUserPath = if ($UserPath) { "$UserPath;$VoskBinDir" } else { $VoskBinDir }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
        $env:Path = "$env:Path;$VoskBinDir"
        Write-Host "Added to PATH (User): $VoskBinDir"
    } else {
        Write-Host "PATH already contains: $VoskBinDir"
    }
} else {
    Write-Host "WARNING: vosk.dll not found. Ensure it is on PATH at runtime."
}

Write-Host ""
Write-Host "=== Setup Complete ==="
Write-Host "Build: cargo build -p gabby"
Write-Host "Run: cargo run --release -p gabby"
