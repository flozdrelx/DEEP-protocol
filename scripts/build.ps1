# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputDirectory = Join-Path $projectRoot 'bin'
$outputExecutable = Join-Path $outputDirectory 'deep.exe'
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'Install Go 1.25 or later and make sure go is available in PATH.'
}
[void](New-Item -ItemType Directory -Path $outputDirectory -Force)
Push-Location -LiteralPath $projectRoot
try {
    & go build -trimpath -o $outputExecutable ./cmd/deep
    if ($LASTEXITCODE -ne 0) {
        throw 'DEEP build failed.'
    }
    Write-Host "DEEP built: $outputExecutable"
} finally {
    Pop-Location
}
