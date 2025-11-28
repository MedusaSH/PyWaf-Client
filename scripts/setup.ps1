param(
    [switch]$SkipDockerCheck
)

$ErrorActionPreference = "Stop"

Write-Host "=== Configuration du WAF ===" -ForegroundColor Cyan

if (-not $SkipDockerCheck) {
    Write-Host "`n1. Verification de Docker..." -ForegroundColor Yellow
    & "$PSScriptRoot\check-docker.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`nERREUR: Docker n'est pas pret. Veuillez resoudre le probleme ci-dessus." -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n2. Verification du fichier .env..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Write-Host "Creation du fichier .env depuis env.example..." -ForegroundColor Cyan
    if (Test-Path "env.example") {
        Copy-Item "env.example" ".env"
        Write-Host "Fichier .env cree. Veuillez le modifier avec vos valeurs." -ForegroundColor Yellow
        Write-Host "Appuyez sur Entree pour continuer apres avoir modifie .env..." -ForegroundColor Yellow
        Read-Host
    } else {
        Write-Host "ERREUR: env.example introuvable" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Fichier .env existe deja" -ForegroundColor Green
}

Write-Host "`n3. Generation d'une SECRET_KEY si necessaire..." -ForegroundColor Yellow
$envContent = Get-Content ".env" -Raw
if ($envContent -match "SECRET_KEY=changeme") {
    Write-Host "Generation d'une nouvelle SECRET_KEY..." -ForegroundColor Cyan
    $secretKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
    $envContent = $envContent -replace "SECRET_KEY=changeme-secret-key-here-generate-a-strong-random-key", "SECRET_KEY=$secretKey"
    Set-Content ".env" -Value $envContent -NoNewline
    Write-Host "SECRET_KEY generee automatiquement" -ForegroundColor Green
}

Write-Host "`n4. Construction des images Docker..." -ForegroundColor Yellow
docker-compose build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR lors de la construction des images" -ForegroundColor Red
    exit 1
}

Write-Host "`n5. Demarrage des services..." -ForegroundColor Yellow
docker-compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR lors du demarrage des services" -ForegroundColor Red
    exit 1
}

Write-Host "`n6. Attente du demarrage de PostgreSQL..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host "`n7. Initialisation de la base de donnees..." -ForegroundColor Yellow
docker-compose exec -T waf-api alembic upgrade head
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR lors de l'initialisation de la base de donnees" -ForegroundColor Red
    Write-Host "Verifiez les logs: docker-compose logs waf-api" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n=== Configuration terminee avec succes! ===" -ForegroundColor Green
Write-Host "`nServices disponibles:" -ForegroundColor Cyan
Write-Host "  - API: http://localhost:8000" -ForegroundColor White
Write-Host "  - API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host "  - Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "`nCommandes utiles:" -ForegroundColor Cyan
Write-Host "  - Voir les logs: docker-compose logs -f" -ForegroundColor White
Write-Host "  - Arreter: docker-compose down" -ForegroundColor White
Write-Host "  - Redemarrer: docker-compose restart" -ForegroundColor White

