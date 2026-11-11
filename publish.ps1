# Publish Mizan to GitHub with the REST API (no git binary required).
param(
    [string]$Owner = "Toufiqtoufiqbo"
)

$ErrorActionPreference = "Stop"
$token = $env:GITHUB_PERSONAL_ACCESS_TOKEN
$headers = @{
    "Authorization" = "Bearer $token"
    "User-Agent"    = "mizan-publisher"
    "Accept"        = "application/vnd.github+json"
}
$api = "https://api.github.com"

function Invoke-Gh {
    param([string]$Method, [string]$Uri, $Body)
    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
    $json = $Body | ConvertTo-Json -Depth 6 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $bytes -ContentType "application/json"
}

function Test-Repo {
    param([string]$Repo)
    try {
        Invoke-RestMethod -Method Get -Uri "$api/repos/$Owner/$Repo" -Headers $headers -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function New-Repo {
    param([string]$Repo, [string]$Description)
    if (Test-Repo $Repo) {
        Write-Host "repo $Repo already exists"
        return
    }
    Invoke-Gh -Method Post -Uri "$api/user/repos" -Body @{
        name            = $Repo
        description     = $Description
        private         = $false
        auto_init       = $true
        license_template = "mit"
    } | Out-Null
    Write-Host "created repo $Repo"
    Start-Sleep -Seconds 3
}

function Push-File {
    param([string]$Repo, [string]$Path, [string]$LocalPath, [string]$Branch = "main", [string]$Message)
    $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($LocalPath))
    $body = @{
        message = $Message
        content = $content
        branch  = $Branch
    }
    try {
        Invoke-Gh -Method Put -Uri "$api/repos/$Owner/$Repo/contents/$Path" -Body $body | Out-Null
        Write-Host "  + $Path"
    } catch {
        Write-Host "  ! $Path -> $($_.Exception.Message)"
    }
}

$root = "C:\Users\Rahim\Desktop\New folder\mizan"

# --------------------------------------------------------------------------- #
# 1. Standalone repository
# --------------------------------------------------------------------------- #
New-Repo -Repo "mizan" -Description "Law-driven API security testing: write-side taint, authority creation, TOCTOU races and reproducible proof bundles. Built on Schemathesis."

$files = @(
    @{ path = "README.md"; local = "$root\README.md" },
    @{ path = "pyproject.toml"; local = "$root\pyproject.toml" },
    @{ path = ".gitignore"; local = "$root\.gitignore" },
    @{ path = "src/mizan/__init__.py"; local = "$root\src\mizan\__init__.py" },
    @{ path = "src/mizan/core.py"; local = "$root\src\mizan\core.py" },
    @{ path = "src/mizan/traffic.py"; local = "$root\src\mizan\traffic.py" },
    @{ path = "src/mizan/taint.py"; local = "$root\src\mizan\taint.py" },
    @{ path = "src/mizan/races.py"; local = "$root\src\mizan\races.py" },
    @{ path = "src/mizan/proof.py"; local = "$root\src\mizan\proof.py" },
    @{ path = "src/mizan/engine.py"; local = "$root\src\mizan\engine.py" },
    @{ path = "src/mizan/cli.py"; local = "$root\src\mizan\cli.py" },
    @{ path = "src/mizan/schemathesis_plugin.py"; local = "$root\src\mizan\schemathesis_plugin.py" },
    @{ path = "src/mizan/schemathesis_hooks.py"; local = "$root\src\mizan\schemathesis_hooks.py" },
    @{ path = "src/mizan/pytest_plugin.py"; local = "$root\src\mizan\pytest_plugin.py" },
    @{ path = "src/mizan/demo/__init__.py"; local = "$root\src\mizan\demo\__init__.py" },
    @{ path = "src/mizan/demo/app.py"; local = "$root\src\mizan\demo\app.py" },
    @{ path = "src/mizan/demo/openapi.json"; local = "$root\src\mizan\demo\openapi.json" },
    @{ path = "tests/test_mizan.py"; local = "$root\tests\test_mizan.py" }
)

Write-Host "Pushing mizan..."
foreach ($file in $files) {
    if (Test-Path $file.local) {
        Push-File -Repo "mizan" -Path $file.path -LocalPath $file.local -Message "Add $file.path"
    } else {
        Write-Host "  ? missing $file.local"
    }
}

# --------------------------------------------------------------------------- #
# 2. Fork of Schemathesis with the law engine
# --------------------------------------------------------------------------- #
if (-not (Test-Repo "schemathesis")) {
    Write-Host "Forking schemathesis/schemathesis..."
    try {
        Invoke-Gh -Method Post -Uri "$api/repos/schemathesis/schemathesis/forks" -Body @{} | Out-Null
        Start-Sleep -Seconds 5
    } catch {
        Write-Host "fork failed: $($_.Exception.Message)"
    }
}

if (Test-Repo "schemathesis") {
    $fork = Invoke-RestMethod -Method Get -Uri "$api/repos/$Owner/schemathesis" -Headers $headers
    $defaultBranch = $fork.default_branch
    $ref = Invoke-RestMethod -Method Get -Uri "$api/repos/$Owner/schemathesis/git/ref/heads/$defaultBranch" -Headers $headers
    $branch = "feat/law-checks"
    try {
        Invoke-Gh -Method Post -Uri "$api/repos/$Owner/schemathesis/git/refs" -Body @{
            ref = "refs/heads/$branch"
            sha = $ref.object.sha
        } | Out-Null
        Write-Host "created branch $branch"
    } catch {
        Write-Host "branch $branch already exists or failed: $($_.Exception.Message)"
    }

    $patch = "$root\fork-patch"
    $forkFiles = @(
        @{ path = "src/schemathesis/laws/__init__.py"; local = "$patch\src\schemathesis\laws\__init__.py" },
        @{ path = "src/schemathesis/laws/core.py"; local = "$patch\src\schemathesis\laws\core.py" },
        @{ path = "src/schemathesis/laws/taint.py"; local = "$patch\src\schemathesis\laws\taint.py" },
        @{ path = "src/schemathesis/laws/races.py"; local = "$patch\src\schemathesis\laws\races.py" },
        @{ path = "src/schemathesis/laws/proof.py"; local = "$patch\src\schemathesis\laws\proof.py" },
        @{ path = "src/schemathesis/laws/checks.py"; local = "$patch\src\schemathesis\laws\checks.py" },
        @{ path = "docs/laws.md"; local = "$patch\docs\laws.md" },
        @{ path = "test/laws/test_laws.py"; local = "$patch\test\laws\test_laws.py" }
    )
    Write-Host "Pushing the law engine to the fork..."
    foreach ($file in $forkFiles) {
        if (Test-Path $file.local) {
            Push-File -Repo "schemathesis" -Path $file.path -LocalPath $file.local -Branch $branch -Message "Add law-driven checks: $file.path"
        }
    }
    Write-Host "fork branch: https://github.com/$Owner/schemathesis/tree/$branch"
} else {
    Write-Host "fork not available"
}
