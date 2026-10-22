# Build the release APK from an ASCII-only staging directory.
#
# Reason: Android Gradle Plugin refuses non-ASCII project paths, and the
# workspace path contains an accented directory.  Source of truth stays in the
# workspace; this script mirrors it to C:\cipher-build, builds, and copies the
# APK back.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\build_apk.ps1

$ErrorActionPreference = "Stop"

$Source = Split-Path -Parent $PSScriptRoot
$Stage = "C:\cipher-build"
$Python = Join-Path $Source ".venv\Scripts\python.exe"
$Flet = Join-Path $Source ".venv\Scripts\flet.exe"

if (-not (Test-Path $Python)) { throw "venv not found at $Python" }

New-Item -ItemType Directory -Force -Path $Stage | Out-Null

# Mirror sources.  Exclude generated/build output so stale artefacts cannot
# leak into the APK.
$rc = Start-Process -FilePath robocopy.exe -ArgumentList @(
    "`"$Source`"", "`"$Stage`"", "/MIR", "/XD", ".venv", "build", ".git",
    "__pycache__", ".pytest_cache", "/XF", "*.pyc", "*.log", "/NFL", "/NDL",
    "/NJH", "/NJS", "/NP"
) -Wait -PassThru -NoNewWindow
if ($rc.ExitCode -gt 7) { throw "robocopy failed: $($rc.ExitCode)" }

# Bake relay configuration into the APK.  Android app processes do not inherit
# the build shell's environment, so a sideloaded release build needs the URL
# and SPKI pins inside the package.  Never commit the generated file.
$relayUrl = $env:CIPHER_RELAY_URL
$relayPins = $env:CIPHER_RELAY_PINS
if ($relayUrl -or $relayPins) {
    $pins = @()
    if ($relayPins) {
        $pins = $relayPins.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    $config = @{ url = $relayUrl; pins = $pins } | ConvertTo-Json
    # Windows PowerShell's `Set-Content -Encoding UTF8` emits a BOM, which
    # `json.loads` rejects.  Write UTF-8 without a BOM.
    $configPath = Join-Path $Stage "app\relay_config.json"
    [System.IO.File]::WriteAllText(
        $configPath, $config, (New-Object System.Text.UTF8Encoding($false))
    )
} else {
    # Do not let a developer's local relay_config.json leak into a build that
    # was not explicitly configured; the app must show the disabled banner.
    Remove-Item -Force (Join-Path $Stage "app\relay_config.json") -ErrorAction SilentlyContinue
}

$env:JAVA_HOME = "C:\Users\Informatics\java\17.0.13+11"
$env:PATH = "C:\Users\Informatics\flutter\3.29.2\bin;$env:PATH"
$env:PYTHONIOENCODING = "utf-8"

# /MIR excludes build directories, so generated Flutter package copies from a
# previous build survive in the staging tree.  They can contain stale source
# (and stale Kotlin packages), so remove them before every build.
#
# `native\build` is created by pip when it builds the local extension wheel.
# Setuptools copies package data into it and does not delete files that were
# removed or renamed upstream, so an old `dev/cipher/native` Kotlin file would
# otherwise be bundled alongside the current `dev/cipher/ciphernative` one.
Remove-Item -Recurse -Force (Join-Path $Stage "app\build") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $Stage "native\build") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $Stage "native\src\cipher_native.egg-info") -ErrorAction SilentlyContinue

Push-Location (Join-Path $Stage "app")
try {
    & $Flet build apk --project cipher --org dev.cipher --product Cipher `
        --build-version 0.1.0 --skip-flutter-doctor --no-rich-output
    if ($LASTEXITCODE -ne 0) { throw "flet build failed: $LASTEXITCODE" }
} finally {
    Pop-Location
}

$apk = Join-Path $Stage "app\build\apk\app-release.apk"
if (-not (Test-Path $apk)) { throw "APK not produced at $apk" }
New-Item -ItemType Directory -Force -Path (Join-Path $Source "app\build\apk") | Out-Null
Copy-Item $apk (Join-Path $Source "app\build\apk\app-release.apk") -Force
Write-Host "APK: $Source\app\build\apk\app-release.apk"
