# SPDX-License-Identifier: Apache-2.0
# Run explicitly to register deep:// for the current Windows user.
[CmdletBinding(SupportsShouldProcess = $true)]
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
$terminalCommand = '"' + $resolvedExecutable + '" open-uri "%1"'
$viewer = Join-Path ([IO.Path]::GetDirectoryName($resolvedExecutable)) 'viewer/DEEP.Viewer.exe'
# Always dispatch through the backend so viewer enable/disable takes effect.
# Recognize the older direct-viewer handler only for this exact installation.
$legacyViewerCommand = '"' + $viewer + '" --deep "' + $resolvedExecutable + '" --config "' + $configuration + '" --uri "%1"'
$command = $terminalCommand
if (Test-Path -LiteralPath $schemeKey) {
    $existingCommand = $null
    if (Test-Path -LiteralPath $commandKey) {
        $existingCommand = (Get-Item -LiteralPath $commandKey).GetValue('')
    }
    if ($existingCommand -ne $command -and $existingCommand -ne $legacyViewerCommand -and -not $ReplaceExisting) {
        throw 'deep:// already has another handler. Use -ReplaceExisting to explicitly replace it with DEEP.'
    }
}
if (-not $PSCmdlet.ShouldProcess('Current-user deep:// handler', 'Register DEEP backend dispatcher')) { return }
[void](New-Item -Path $schemeKey -Force)
Set-Item -LiteralPath $schemeKey -Value 'URL:DEEP Protocol'
[void](New-ItemProperty -LiteralPath $schemeKey -Name 'URL Protocol' -Value '' -PropertyType String -Force)
[void](New-Item -Path $commandKey -Force)
Set-Item -LiteralPath $commandKey -Value $command
Write-Host "deep:// registered for the current user with $resolvedExecutable"
Write-Host "Client configuration: $configuration"
Write-Host "The viewer remains opt-in: deep viewer enable. External browsers can register their own handler."
