# confirm-scope.ps1 — ZeroProtocol-style scope confirmation for the scope-guard hook.
#
# When notes/scope.json has "requireConfirm": true, the hook blocks all live in-scope testing until
# the current scope has been confirmed. This script shows you the scope so you can review it, then
# writes the SHA-256 the hook expects into "confirmedScope". Run it once in Phase 0, and again every
# time you edit inScope / outOfScope / denyUnlisted — any edit invalidates the old confirmation.
#
# The hash is computed identically here and in .claude/hooks/scope-guard.mjs: the three arrays,
# lowercased, de-duplicated, ordinal-sorted, joined, then SHA-256 hex.
[CmdletBinding()]
param(
  [string]$ScopeFile = '',
  [switch]$Yes   # skip the interactive confirmation (for scripted setup)
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 can leave $PSScriptRoot empty in a parameter default, so resolve it here
if (-not $ScopeFile) { $ScopeFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..\notes\scope.json' }
if (-not (Test-Path $ScopeFile)) { Write-Error "scope.json not found at $ScopeFile"; exit 1 }
$scope = [IO.File]::ReadAllText((Resolve-Path $ScopeFile)) | ConvertFrom-Json

function Canon($arr) {
  $list = @()
  # ToLowerInvariant: ToLower() follows the system culture (a Turkish "I" would change the hash)
  foreach ($x in @($arr)) { $t = "$x".Trim().ToLowerInvariant(); if ($t) { $list += $t } }
  $set = [System.Collections.Generic.HashSet[string]]::new([string[]]$list)
  $sorted = [string[]]@($set)
  [Array]::Sort($sorted, [StringComparer]::Ordinal)
  return ($sorted -join ',')
}

$canon = "inScope=$(Canon $scope.inScope)|outOfScope=$(Canon $scope.outOfScope)|denyUnlisted=$(Canon $scope.denyUnlisted)"
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canon)))).Replace('-', '').ToLower()

Write-Host ''
Write-Host 'Scope to confirm:' -ForegroundColor Cyan
Write-Host ('  IN SCOPE     : ' + (@($scope.inScope)     -join ', '))
Write-Host ('  OUT OF SCOPE : ' + (@($scope.outOfScope)  -join ', '))
Write-Host ('  DENY UNLISTED: ' + (@($scope.denyUnlisted) -join ', '))
Write-Host ''

if ($scope.confirmedScope -eq $hash) {
  Write-Host 'Already confirmed — scope unchanged since last confirmation. Nothing to do.' -ForegroundColor Green
  exit 0
}

if (-not $Yes) {
  $ans = Read-Host 'Confirm this is the authorized scope you are allowed to test? (yes/no)'
  if ($ans -notin @('y', 'yes')) { Write-Host 'Not confirmed. No change written.' -ForegroundColor Yellow; exit 1 }
}

if ($scope.PSObject.Properties.Name -notcontains 'confirmedScope') {
  $scope | Add-Member -NotePropertyName confirmedScope -NotePropertyValue ''
}
$scope.confirmedScope = $hash
# UTF-8 without a BOM: Windows PowerShell 5.1's Set-Content -Encoding UTF8 adds one
[IO.File]::WriteAllText((Resolve-Path $ScopeFile), ($scope | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
Write-Host "Confirmed. Wrote confirmedScope = $hash" -ForegroundColor Green
