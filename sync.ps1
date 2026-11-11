# Sync the working tree to the GitHub repository (no git binary required).
param(
    [string]$Owner = "Toufiqtoufiqbo",
    [string]$Repo = "mizan",
    [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"
$token = $env:GITHUB_PERSONAL_ACCESS_TOKEN
$headers = @{
    "Authorization" = "Bearer $token"
    "User-Agent"    = "mizan-publisher"
    "Accept"        = "application/vnd.github+json"
}
$api = "https://api.github.com"
$root = "C:\Users\Rahim\Desktop\New folder\mizan"

function Invoke-Gh {
    param([string]$Method, [string]$Uri, $Body)
    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
    $json = $Body | ConvertTo-Json -Depth 6 -Compress
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType "application/json"
}

function Sync-File {
    param([string]$Path, [string]$LocalPath)
    if (-not (Test-Path $LocalPath)) {
        Write-Host "  ? missing $LocalPath"
        return
    }
    $sha = $null
    try {
        $existing = Invoke-RestMethod -Method Get -Uri "$api/repos/$Owner/$Repo/contents/$Path" -Headers $headers -ErrorAction Stop
        $sha = $existing.sha
    } catch {
        $sha = $null
    }
    $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($LocalPath))
    $body = @{
        message = "Sync $Path"
        content = $content
        branch  = $Branch
    }
    if ($sha) {
        $body.sha = $sha
    }
    try {
        Invoke-Gh -Method Put -Uri "$api/repos/$Owner/$Repo/contents/$Path" -Body $body | Out-Null
        Write-Host "  + $Path"
    } catch {
        Write-Host "  ! $Path -> $($_.Exception.Message)"
    }
}

$files = @(
    "README.md",
    "ROADMAP.md",
    "pyproject.toml",
    ".gitignore",
    "src/mizan/__init__.py",
    "src/mizan/core.py",
    "src/mizan/traffic.py",
    "src/mizan/taint.py",
    "src/mizan/races.py",
    "src/mizan/proof.py",
    "src/mizan/engine.py",
    "src/mizan/cli.py",
    "src/mizan/identity.py",
    "src/mizan/recorder.py",
    "src/mizan/tokens.py",
    "src/mizan/twin.py",
    "src/mizan/proxy.py",
    "src/mizan/attribution.py",
    "src/mizan/learning.py",
    "src/mizan/parallel.py",
    "src/mizan/search.py",
    "src/mizan/postgres_audit.py",
    "src/mizan/regression.py",
    "src/mizan/patching.py",
    "src/mizan/schemathesis_plugin.py",
    "src/mizan/schemathesis_hooks.py",
    "src/mizan/pytest_plugin.py",
    "src/mizan/demo/__init__.py",
    "src/mizan/demo/app.py",
    "src/mizan/demo/server.py",
    "src/mizan/demo/openapi.json",
    "src/mizan/benchmark/__init__.py",
    "src/mizan/benchmark/apps.py",
    "src/mizan/benchmark/evaluate.py",
    "src/mizan/benchmark/generator.py",
    "tests/test_mizan.py",
    "tests/test_benchmark.py",
    "tests/test_regression.py",
    "tests/test_recorder.py",
    "tests/test_twin.py",
    "tests/test_postgres_audit.py",
    "tests/test_postgres_roundtrip.py",
    "tests/test_parallel.py",
    "tests/test_search.py",
    "tests/test_search_benchmark.py",
    ".github/workflows/mizan.yml",
    "authzbugs-report/report.md",
    "authzbugs-report/report.json"
)

Write-Host "Syncing $Repo ..."
foreach ($file in $files) {
    Sync-File -Path $file -LocalPath (Join-Path $root $file)
}
Write-Host "done"

