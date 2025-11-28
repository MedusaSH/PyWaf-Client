Write-Host "Verification de Docker..." -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "ERREUR: Docker n'est pas installe ou n'est pas dans le PATH" -ForegroundColor Red
    Write-Host "Veuillez installer Docker Desktop depuis: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host "Docker est installe" -ForegroundColor Green

try {
    $dockerVersion = docker --version
    Write-Host "Version Docker: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "ERREUR: Impossible d'obtenir la version de Docker" -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = "SilentlyContinue"
$dockerCheck = docker ps 2>&1
$dockerExitCode = $LASTEXITCODE
$ErrorActionPreference = "Continue"

$isDockerRunning = $true
$errorMessage = ""

if ($dockerExitCode -ne 0) {
    $isDockerRunning = $false
    if ($dockerCheck) {
        $errorMessage = $dockerCheck.ToString()
    }
} elseif ($dockerCheck -match "error during connect" -or $dockerCheck -match "Le fichier spécifié est introuvable" -or $dockerCheck -match "Cannot connect to the Docker daemon") {
    $isDockerRunning = $false
    $errorMessage = $dockerCheck.ToString()
}

if (-not $isDockerRunning) {
    Write-Host "ERREUR: Docker Desktop n'est pas demarre ou n'est pas accessible" -ForegroundColor Red
    if ($errorMessage) {
        Write-Host "Message d'erreur: $errorMessage" -ForegroundColor Yellow
    }
    Write-Host "`nVeuillez demarrer Docker Desktop et attendre qu'il soit pret" -ForegroundColor Yellow
    Write-Host "Tentative de demarrage de Docker Desktop..." -ForegroundColor Cyan
    
    $dockerDesktopPaths = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    )
    
    $dockerDesktopFound = $false
    foreach ($dockerDesktopPath in $dockerDesktopPaths) {
        if (Test-Path $dockerDesktopPath) {
            Write-Host "Demarrage de Docker Desktop depuis: $dockerDesktopPath" -ForegroundColor Cyan
            Start-Process $dockerDesktopPath
            $dockerDesktopFound = $true
            break
        }
    }
    
    if ($dockerDesktopFound) {
        Write-Host "`nDocker Desktop est en cours de demarrage..." -ForegroundColor Yellow
        Write-Host "Attendez 30-60 secondes que Docker Desktop soit completement demarre" -ForegroundColor Yellow
        Write-Host "Vous pouvez verifier l'etat dans la barre des taches (icone Docker)" -ForegroundColor Yellow
        Write-Host "`nRelancez ce script une fois Docker Desktop pret" -ForegroundColor Cyan
        Write-Host "Ou utilisez: .\scripts\wait-docker.ps1" -ForegroundColor Cyan
    } else {
        Write-Host "`nImpossible de trouver Docker Desktop automatiquement." -ForegroundColor Red
        Write-Host "Veuillez le demarrer manuellement depuis le menu Demarrer" -ForegroundColor Yellow
    }
    exit 1
} else {
    Write-Host "Docker Desktop est demarre et fonctionne" -ForegroundColor Green
}

if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "ERREUR: docker-compose n'est pas installe" -ForegroundColor Red
    Write-Host "Essayez d'utiliser: docker compose (sans tiret)" -ForegroundColor Yellow
    exit 1
}

Write-Host "docker-compose est disponible" -ForegroundColor Green

Write-Host "`nTous les pre-requis Docker sont OK!" -ForegroundColor Green

