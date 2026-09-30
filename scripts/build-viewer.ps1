# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param([string]$Runtime = 'win-x64', [string]$OutputDirectory = '')
$ErrorActionPreference = 'Stop'
if ($Runtime -notin @('win-x64', 'win-arm64')) { throw 'Use win-x64 or win-arm64.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Install the .NET 10 SDK to build the viewer.' }
if ($OutputDirectory -eq '') { $OutputDirectory = Join-Path $projectRoot 'bin/viewer' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$project = Join-Path $projectRoot 'viewer/DEEP.Viewer/DEEP.Viewer.csproj'
& dotnet publish $project -c Release -r $Runtime --self-contained true -p:RestoreLockedMode=true -o $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw 'DEEP viewer build failed.' }

# Preserve the exact redistributed package licenses in the portable output.
$cacheLine = & dotnet nuget locals global-packages --list --force-english-output
if ($LASTEXITCODE -ne 0) { throw 'Could not locate NuGet package licenses.' }
$cache = $cacheLine -replace '^global-packages:\s*', ''
$licenses = Join-Path $OutputDirectory 'licenses'
[void][IO.Directory]::CreateDirectory($licenses)
[xml]$projectXml = Get-Content -LiteralPath $project -Raw
$package = $projectXml.Project.ItemGroup.PackageReference | Where-Object { $_.Include -eq 'Microsoft.Web.WebView2' }
$webPackage = Join-Path $cache ('microsoft.web.webview2/' + $package.Version)
Copy-Item -LiteralPath (Join-Path $webPackage 'LICENSE.txt') -Destination (Join-Path $licenses 'WebView2-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $webPackage 'NOTICE.txt') -Destination (Join-Path $licenses 'WebView2-NOTICE.txt')
$runtimeConfig = Get-Content -LiteralPath (Join-Path $OutputDirectory 'DEEP.Viewer.runtimeconfig.json') -Raw | ConvertFrom-Json
foreach ($framework in $runtimeConfig.runtimeOptions.includedFrameworks) {
    $runtimePackage = Join-Path $cache ($framework.name.ToLowerInvariant() + '.runtime.' + $Runtime + '/' + $framework.version)
    $license = Join-Path $runtimePackage 'LICENSE.TXT'
    if (-not (Test-Path -LiteralPath $license)) { $license = Join-Path $runtimePackage 'LICENSE' }
    Copy-Item -LiteralPath $license -Destination (Join-Path $licenses ($framework.name + '-LICENSE.txt'))
    $notices = Join-Path $runtimePackage 'THIRD-PARTY-NOTICES.TXT'
    if (Test-Path -LiteralPath $notices) {
        Copy-Item -LiteralPath $notices -Destination (Join-Path $licenses ($framework.name + '-NOTICES.txt'))
    }
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination (Join-Path $licenses 'DEEP-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $projectRoot 'NOTICE') -Destination (Join-Path $licenses 'DEEP-NOTICE.txt')
Write-Host "Viewer built: $OutputDirectory"
Write-Host 'The Microsoft Edge WebView2 Runtime must be installed on the target computer.'
