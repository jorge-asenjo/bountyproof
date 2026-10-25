# ask-gemini.ps1 - Delegate a READ-ONLY discovery/audit shard to Gemini.
# Runs in plan (read-only) mode by default: Gemini cannot edit files or run network attacks.
# Usage:
#   .\ask-gemini.ps1 -PromptFile reference\worker-prompts-B.txt -Shard "auth controllers in source/app/controllers"
#   .\ask-gemini.ps1 -Prompt "Audit source/ for IDOR in tenant resolution" -Json
param(
    [string]$Prompt,
    [string]$PromptFile,
    [string]$Shard = "",
    [string]$Model = "gemini-2.5-pro",
    [string]$IncludeDirs = "source",
    [switch]$Json,
    [switch]$AllowWrite   # opt-in only; default is read-only (plan mode)
)
$ErrorActionPreference = "Stop"

if ($PromptFile) { $Prompt = Get-Content $PromptFile -Raw }
if (-not $Prompt) { Write-Error "Provide -Prompt or -PromptFile"; exit 1 }
if ($Shard) { $Prompt = "$Prompt`n`n## Assigned shard`n$Shard" }

$gemArgs = @("-p", $Prompt, "-m", $Model, "--include-directories", $IncludeDirs, "--skip-trust")
if (-not $AllowWrite) { $gemArgs += @("--approval-mode", "plan") }   # read-only
if ($Json) { $gemArgs += @("-o", "json") }

Write-Host "[ask-gemini] model=$Model readonly=$(-not $AllowWrite) dirs=$IncludeDirs" -ForegroundColor Cyan
& gemini @gemArgs
