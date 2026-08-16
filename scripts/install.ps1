# Install a pre-built oauth2c release. Go is not required.
#
#   irm https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.ps1 | iex
#
# Optional:
#   $env:OAUTH2C_VERSION = "v2.1.0"   # pin a release (default: latest)
#   $env:OAUTH2C_BINDIR = "$env:LOCALAPPDATA\oauth2c"  # install directory
$ErrorActionPreference = "Stop"

$Repo = "sukujgrg/oauth2c"
$BinDir = if ($env:OAUTH2C_BINDIR) { $env:OAUTH2C_BINDIR } else { Join-Path $env:LOCALAPPDATA "oauth2c" }
$Version = $env:OAUTH2C_VERSION

switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $ArchName = "x86_64" }
    "ARM64" { $ArchName = "arm64" }
    "ARM" { $ArchName = "arm" }
    default {
        throw "oauth2c install: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'"
    }
}

if (-not $Version) {
    $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $latest.tag_name
}
if (-not $Version) {
    throw "oauth2c install: could not determine the latest release"
}

$versionNum = $Version.TrimStart("v")
$assetZip = "oauth2c_${versionNum}_Windows_${ArchName}.zip"
$assetTar = "oauth2c_${versionNum}_Windows_${ArchName}.tar.gz"
$base = "https://github.com/$Repo/releases/download/$Version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("oauth2c-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

function Get-ChecksumLine([string]$sumsPath, [string]$name) {
    return Select-String -Path $sumsPath -Pattern "[A-Fa-f0-9]{64}\s+$([regex]::Escape($name))$"
}

try {
    Write-Host "Installing oauth2c $Version (Windows/$ArchName) to $BinDir"
    $sums = Join-Path $tmp "checksums.txt"
    Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile $sums

    # v2.0.0 shipped Windows as tar.gz; later releases use zip.
    $zipLine = Get-ChecksumLine $sums $assetZip
    $tarLine = Get-ChecksumLine $sums $assetTar
    if ($zipLine) {
        $asset = $assetZip
        $expectedLine = $zipLine
    }
    elseif ($tarLine) {
        $asset = $assetTar
        $expectedLine = $tarLine
    }
    else {
        throw "oauth2c install: no Windows/$ArchName archive in checksums.txt"
    }

    $archive = Join-Path $tmp $asset
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $archive

    $hash = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLower()
    $want = $expectedLine.Line.Split(" ", 2)[0].ToLower()
    if ($hash -ne $want) {
        throw "oauth2c install: checksum mismatch for $asset"
    }

    if ($asset.EndsWith(".zip")) {
        Expand-Archive -Path $archive -DestinationPath $tmp -Force
    }
    else {
        tar -xzf $archive -C $tmp
        if ($LASTEXITCODE -ne 0) {
            throw "oauth2c install: failed to extract $asset"
        }
    }
    $src = Get-ChildItem -Path $tmp -Recurse -Filter "oauth2c.exe" | Select-Object -First 1
    if (-not $src) {
        throw "oauth2c install: archive did not contain oauth2c.exe"
    }

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    Copy-Item -Force $src.FullName (Join-Path $BinDir "oauth2c.exe")

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $parts = $userPath -split ";" | Where-Object { $_ -ne "" }
    if ($parts -notcontains $BinDir) {
        [Environment]::SetEnvironmentVariable("Path", ($parts + $BinDir) -join ";", "User")
        $env:Path = "$BinDir;$env:Path"
        Write-Host "Added $BinDir to your user PATH. Open a new terminal if oauth2c is not found."
    }

    & (Join-Path $BinDir "oauth2c.exe") version
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
