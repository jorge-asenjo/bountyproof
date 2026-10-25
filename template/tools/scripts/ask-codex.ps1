# ask-codex.ps1 - Delegate a reasoning/validation/threat-model shard to Codex (non-interactive).
# Defaults to read-only disk access for discovery. Codex is best for repo-specific threat
# modeling, validation reasoning, and patch proposals.
# Usage:
#   .\ask-codex.ps1 -Prompt "Build a threat model for source/ focusing on SSRF in webhook handlers"
#   .\ask-codex.ps1 -PromptFile shard.txt -Model gpt-5-codex
#   .\ask-codex.ps1 -Review        # built-in code review of current repo
param(
    [string]$Prompt,
    [string]$PromptFile,
    [string]$Shard = "",
    [string]$Model = "gpt-5-codex",
    [switch]$Review,
    [switch]$AllowWrite   # opt-in only; default is read-only sandbox
)
$ErrorActionPreference = "Stop"

if ($Review) {
    Write-Host "[ask-codex] running code review on current repo" -ForegroundColor Cyan
    & codex exec review
    exit $LASTEXITCODE
}

if ($PromptFile) { $Prompt = Get-Content $PromptFile -Raw }
if (-not $Prompt) { Write-Error "Provide -Prompt, -PromptFile, or -Review"; exit 1 }
if ($Shard) { $Prompt = "$Prompt`n`n## Assigned shard`n$Shard" }

$codexArgs = @("exec", "-m", $Model)
if (-not $AllowWrite) { $codexArgs += @("-c", 'sandbox_permissions=["disk-full-read-access"]') }
$codexArgs += $Prompt

Write-Host "[ask-codex] model=$Model readonly=$(-not $AllowWrite)" -ForegroundColor Cyan
& codex @codexArgs
