$API_URL = "http://localhost:8000"
$ENDPOINT = "/api/test"

Write-Host "=== Test Anti-DDoS WAF ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Test Rate Limiting Basique" -ForegroundColor Yellow
Write-Host "Envoi de 150 requêtes rapides..."
$jobs = @()
for ($i = 1; $i -le 150; $i++) {
    $jobs += Start-Job -ScriptBlock {
        param($url)
        try {
            $response = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            return $response.StatusCode
        } catch {
            return $_.Exception.Response.StatusCode.value__
        }
    } -ArgumentList "$using:API_URL$using:ENDPOINT"
}
$results = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job
$results | Group-Object | Format-Table Count, Name
Write-Host ""

Write-Host "2. Test Burst Limiting" -ForegroundColor Yellow
Write-Host "Envoi de 60 requêtes en 1 seconde..."
$jobs = @()
for ($i = 1; $i -le 60; $i++) {
    $jobs += Start-Job -ScriptBlock {
        param($url)
        try {
            $response = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            return $response.StatusCode
        } catch {
            return $_.Exception.Response.StatusCode.value__
        }
    } -ArgumentList "$using:API_URL$using:ENDPOINT"
}
$results = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job
$results | Group-Object | Format-Table Count, Name
Write-Host ""

Write-Host "3. Test avec User-Agent suspect" -ForegroundColor Yellow
Write-Host "Envoi de requêtes avec User-Agent de bot..."
$headers = @{
    "User-Agent" = "python-requests/2.28.1"
}
for ($i = 1; $i -le 50; $i++) {
    try {
        Invoke-WebRequest -Uri "$API_URL$ENDPOINT" -Headers $headers -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}
Write-Host ""

Write-Host "4. Test avec patterns suspects" -ForegroundColor Yellow
Write-Host "Envoi de requêtes avec payloads suspects..."
Invoke-WebRequest -Uri "$API_URL$ENDPOINT?test=<script>alert(1)</script>" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
Invoke-WebRequest -Uri "$API_URL$ENDPOINT?test=1' OR '1'='1" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
Invoke-WebRequest -Uri "$API_URL$ENDPOINT?test=../../etc/passwd" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
Write-Host ""

Write-Host "5. Test TLS Fingerprinting" -ForegroundColor Yellow
Write-Host "Vérification des fingerprints..."
$tlsHeaders = @{
    "X-TLS-Version" = "TLSv1.3"
    "X-TLS-Cipher-Suites" = "TLS_AES_256_GCM_SHA384"
    "X-TLS-Extensions" = "server_name,extended_master_secret"
}
Invoke-WebRequest -Uri "$API_URL$ENDPOINT" -Headers $tlsHeaders -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
Write-Host ""

Write-Host "Tests terminés. Vérifiez les logs et le dashboard pour les résultats." -ForegroundColor Green

