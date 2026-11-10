<#
.SYNOPSIS
    Rehearsed live demo for the phishtriage talk. Works with no network.

.DESCRIPTION
    Runs a fixed sequence of commands, pausing before each one so the
    speaker controls the pace. Everything runs with --offline, so a dead
    conference Wi-Fi changes nothing. Press Enter to run the next step,
    "s" + Enter to skip it, "q" + Enter to stop.

    From the repo root:
        powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
        powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -From 4   # resume at step 4

    Tip: set the terminal to about 150 columns and a large font before starting.
#>
param(
    [int]$From = 1
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# uv may be installed for the user but not on PATH in a fresh shell.
$uvBin = Join-Path $env:USERPROFILE ".local\bin"
if ((Test-Path $uvBin) -and -not ($env:Path -split ";" -contains $uvBin)) {
    $env:Path = "$uvBin;$env:Path"
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv not found. Install it or add it to PATH first." -ForegroundColor Red
    exit 1
}

$OutDir = Join-Path $Root "out\demo"
New-Item -ItemType Directory -Force $OutDir | Out-Null
$HtmlReport = Join-Path $OutDir "mychart.html"

$Steps = @(
    @{
        Title = "Every rule is a line of YAML, with a weight, a reason, and an ATT&CK technique"
        Say   = "No ML. If it scores a point, I can tell you which line of this file did it."
        Cmd   = "uv run phishtriage rules"
    },
    @{
        Title = "Authenticated is not aligned: DKIM passes, for someone else's domain"
        Say   = "The DKIM signature is valid. It just belongs to an unrelated domain. DMARC catches it."
        Cmd   = "uv run phishtriage analyze samples/phish/10-dmarc-fail-dkim-unrelated.eml --offline"
    },
    @{
        Title = "A real one: 'MyChart' Medicare lure, seven-label bounce domain"
        Say   = "SPF passes, for a domain nobody sees. Display name says MyChart; the sender doesn't."
        Cmd   = "uv run phishtriage analyze samples/phish/real-01-mychart-medicare-kit.eml --offline --html `"$HtmlReport`""
        After = { if (Test-Path $HtmlReport) { Start-Process $HtmlReport } }
    },
    @{
        Title = "The whole corpus: 18 synthetic + 15 real, one command"
        Say   = "18 for 18 on mail I wrote. 10 for 15 on mail I got. Guess which number matters."
        Cmd   = "uv run phishtriage batch samples --offline"
    },
    @{
        Title = "The miss: a job scam from a classmate's compromised university account"
        Say   = "Every infrastructure check passes, because the infrastructure is fine. Only the words are wrong."
        Cmd   = "uv run phishtriage analyze samples/phish/real-02-uc-account-job-scam-admin.eml --offline"
    },
    @{
        Title = "So just weight the words more? Measure it first."
        Say   = "Doubling content weight catches one more scam and makes a real internship email SUSPICIOUS."
        Cmd   = "uv run phishtriage batch samples --offline --compare rules/examples/content-heavy.yaml"
    },
    @{
        Title = "Bonus: the email is attacker input, all the way to the last line of output"
        Say   = "This subject used to crash my own report. Rich read it as markup. Now it's just text."
        Cmd   = "uv run phishtriage analyze tests/fixtures/hostile-subject.eml --offline"
    }
)

for ($i = $From - 1; $i -lt $Steps.Count; $i++) {
    $step = $Steps[$i]
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host ("[{0}/{1}] {2}" -f ($i + 1), $Steps.Count, $step.Title) -ForegroundColor Cyan
    Write-Host ("      " + $step.Say) -ForegroundColor DarkGray
    Write-Host ("  > " + $step.Cmd) -ForegroundColor Green
    $answer = Read-Host "Enter to run, s to skip, q to quit"
    if ($answer -eq "q") { break }
    if ($answer -eq "s") { continue }
    Clear-Host
    Write-Host ("> " + $step.Cmd) -ForegroundColor Green
    Invoke-Expression $step.Cmd
    if ($step.After) { & $step.After }
}

Write-Host ""
Write-Host "Demo complete. HTML report: $HtmlReport" -ForegroundColor Cyan
