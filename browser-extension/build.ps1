<#
.SYNOPSIS
    Pubblica CffVaultManager.Extension.CryptoHost e copia gli asset generati (_framework/) dentro
    browser-extension/offscreen/, dove offscreen.html li carica. Da eseguire prima di caricare
    l'estensione come "non pacchettizzata" in Chrome, e ogni volta che CffVaultManager.Crypto
    cambia. _framework/ non è committato (vedi .gitignore) perché rigenerato da questo script.
#>
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repoRoot "src/CffVaultManager.Extension.CryptoHost/CffVaultManager.Extension.CryptoHost.csproj"
$publishDir = Join-Path $PSScriptRoot ".publish"
$frameworkDest = Join-Path $PSScriptRoot "offscreen/_framework"

if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

dotnet publish $project -c $Configuration -o $publishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish fallito" }

$frameworkSource = Join-Path $publishDir "wwwroot/_framework"
if (-not (Test-Path $frameworkSource)) { throw "Output pubblicato inatteso: $frameworkSource non trovato" }

if (Test-Path $frameworkDest) { Remove-Item $frameworkDest -Recurse -Force }
Copy-Item $frameworkSource $frameworkDest -Recurse

Remove-Item $publishDir -Recurse -Force

Write-Host "Host crypto offscreen aggiornato: $frameworkDest"
