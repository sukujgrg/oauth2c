# Install a pre-built oauth2c release. Go is not required.
#
#   irm https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.ps1 | iex
#
# Optional:
#   $env:OAUTH2C_VERSION = "v2.0.0"   # pin a release (default: latest)
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
$asset = "oauth2c_${versionNum}_Windows_${ArchName}.zip"
$base = "https://github.com/$Repo/releases/download/$Version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("oauth2c-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    Write-Host "Installing oauth2c $Version (Windows/$ArchName) to $BinDir"
    $zip = Join-Path $tmp $asset
    $sums = Join-Path $tmp "checksums.txt"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $zip
    Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile $sums

    $expected = (Select-String -Path $sums -Pattern "[A-Fa-f0-9]{64}\s+$([regex]::Escape($asset))$").Matches
    if ($expected.Count -eq 1) {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
        $want = $expected[0].Value.Split(" ", 2)[0].ToLower()
        if ($hash -ne $want) {
            throw "oauth2c install: checksum mismatch for $asset"
        }
    }
    else {
        Write-Warning "oauth2c install: checksum not found for $asset; skipping verify"
    }

    Expand-Archive -Path $zip -DestinationPath $tmp -Force
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
