# SPDX-License-Identifier: Apache-2.0
# Run explicitly to register deep:// for the current Windows user.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,
    [switch]$ReplaceExisting
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This script only registers URI schemes on Windows.'
}
$resolvedExecutable = (Resolve-Path -LiteralPath $Executable).Path
if (-not (Test-Path -LiteralPath $resolvedExecutable -PathType Leaf)) {
    throw 'Executable must point to the compiled deep.exe file.'
}
if ([System.IO.Path]::GetExtension($resolvedExecutable) -ne '.exe') {
    throw 'Executable must be an .exe file.'
}
$configuration = Join-Path ([System.IO.Path]::GetDirectoryName($resolvedExecutable)) 'config.json'
if (-not (Test-Path -LiteralPath $configuration -PathType Leaf)) {
    throw "First copy a trusted client.json to $configuration."
}
$schemeKey = 'HKCU:\Software\Classes\deep'
$commandKey = Join-Path $schemeKey 'shell\open\command'
$command = '"' + $resolvedExecutable + '" open-uri "%1"'
if (Test-Path -LiteralPath $schemeKey) {
    $existingCommand = $null
    if (Test-Path -LiteralPath $commandKey) {
        $existingCommand = (Get-Item -LiteralPath $commandKey).GetValue('')
    }
    if ($existingCommand -ne $command -and -not $ReplaceExisting) {
        throw 'deep:// already has another handler. Use -ReplaceExisting to explicitly replace it with DEEP V2.'
    }
}
[void](New-Item -Path $schemeKey -Force)
Set-Item -LiteralPath $schemeKey -Value 'URL:DEEP Protocol'
[void](New-ItemProperty -LiteralPath $schemeKey -Name 'URL Protocol' -Value '' -PropertyType String -Force)
[void](New-Item -Path $commandKey -Force)
Set-Item -LiteralPath $commandKey -Value $command
Write-Host "deep:// registered for the current user with $resolvedExecutable"
Write-Host "Client configuration: $configuration"
