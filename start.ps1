param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

Write-Host "=== Démarrage du WAF ===" -ForegroundColor Cyan

Write-Host "`n1. Vérification de Docker..." -ForegroundColor Yellow
& "$PSScriptRoot\scripts\check-docker.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nERREUR: Docker n'est pas prêt." -ForegroundColor Red
    Write-Host "Tentative d'attente de Docker Desktop..." -ForegroundColor Yellow
    & "$PSScriptRoot\scripts\wait-docker.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERREUR: Impossible de démarrer Docker Desktop." -ForegroundColor Red
        exit 1
    }
}

if ($Clean) {
    Write-Host "`n2. Nettoyage de l'environnement..." -ForegroundColor Yellow
    docker-compose down -v
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERREUR lors du nettoyage" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n3. Démarrage des services..." -ForegroundColor Yellow
docker-compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR lors du démarrage des services" -ForegroundColor Red
    exit 1
}

Write-Host "`n4. Attente que les services soient prêts..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
$allHealthy = $false

while ($attempt -lt $maxAttempts -and -not $allHealthy) {
    Start-Sleep -Seconds 2
    $attempt++
    
    $status = docker-compose ps --format json | ConvertFrom-Json
    $unhealthy = $status | Where-Object { $_.Health -ne "healthy" -and $_.Service -match "postgres|redis" }
    
    if ($unhealthy.Count -eq 0) {
        $allHealthy = $true
    } else {
        Write-Host "Attente des services... ($attempt/$maxAttempts)" -ForegroundColor Yellow
    }
}

if (-not $allHealthy) {
    Write-Host "TIMEOUT: Les services ne sont pas prêts" -ForegroundColor Red
    Write-Host "Vérifiez les logs: docker-compose logs" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n5. Vérification de l'API..." -ForegroundColor Yellow
$apiHealthy = $false
$attempt = 0

while ($attempt -lt 10 -and -not $apiHealthy) {
    Start-Sleep -Seconds 2
    $attempt++
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $apiHealthy = $true
        }
    } catch {
        Write-Host "Attente de l'API... ($attempt/10)" -ForegroundColor Yellow
    }
}

if (-not $apiHealthy) {
    Write-Host "ERREUR: L'API ne répond pas" -ForegroundColor Red
    Write-Host "Vérifiez les logs: docker-compose logs waf-api" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n=== WAF démarré avec succès! ===" -ForegroundColor Green
Write-Host "`nServices disponibles:" -ForegroundColor Cyan
Write-Host "  - API: http://localhost:8000" -ForegroundColor White
Write-Host "  - API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host "`nCommandes utiles:" -ForegroundColor Cyan
Write-Host "  - CLI: python waf.py status" -ForegroundColor White
Write-Host "  - Voir les logs: python waf.py logs" -ForegroundColor White
Write-Host "  - Arrêter: python waf.py stop" -ForegroundColor White
Write-Host "  - Redémarrer: python waf.py restart" -ForegroundColor White
Write-Host "  - Nettoyer et redémarrer: .\start.ps1 -Clean" -ForegroundColor White
