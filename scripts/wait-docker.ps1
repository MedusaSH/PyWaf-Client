Write-Host "Attente du demarrage de Docker Desktop..." -ForegroundColor Cyan
Write-Host "Appuyez sur Ctrl+C pour annuler" -ForegroundColor Yellow

$maxAttempts = 60
$attempt = 0

while ($attempt -lt $maxAttempts) {
    $ErrorActionPreference = "SilentlyContinue"
    $dockerCheck = docker ps 2>&1
    $dockerExitCode = $LASTEXITCODE
    $ErrorActionPreference = "Continue"
    
    $isReady = $dockerExitCode -eq 0
    if ($dockerCheck) {
        $checkStr = $dockerCheck.ToString()
        if ($checkStr -match "error during connect" -or $checkStr -match "Le fichier spécifié est introuvable") {
            $isReady = $false
        }
    }
    
    if ($isReady) {
        Write-Host "`nDocker Desktop est pret!" -ForegroundColor Green
        exit 0
    }
    
    $attempt++
    $remaining = $maxAttempts - $attempt
    Write-Host "Tentative $attempt/$maxAttempts - Attente de Docker Desktop... ($remaining secondes restantes)" -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

Write-Host "`nTIMEOUT: Docker Desktop n'a pas demarre dans les delais" -ForegroundColor Red
Write-Host "Veuillez verifier manuellement que Docker Desktop est demarre" -ForegroundColor Yellow
exit 1

