#!/bin/bash

API_URL="http://localhost:8000"
ENDPOINT="/api/test"

echo "=== Test Anti-DDoS WAF ==="
echo ""

echo "1. Test Rate Limiting Basique"
echo "Envoi de 150 requêtes rapides..."
for i in {1..150}; do
    curl -s -o /dev/null -w "%{http_code}\n" "$API_URL$ENDPOINT" &
done
wait
echo ""

echo "2. Test Burst Limiting"
echo "Envoi de 60 requêtes en 1 seconde..."
for i in {1..60}; do
    curl -s -o /dev/null -w "%{http_code}\n" "$API_URL$ENDPOINT" &
done
wait
echo ""

echo "3. Test avec User-Agent suspect"
echo "Envoi de requêtes avec User-Agent de bot..."
for i in {1..50}; do
    curl -s -o /dev/null -H "User-Agent: python-requests/2.28.1" "$API_URL$ENDPOINT" &
done
wait
echo ""

echo "4. Test avec patterns suspects"
echo "Envoi de requêtes avec payloads suspects..."
curl -s "$API_URL$ENDPOINT?test=<script>alert(1)</script>"
curl -s "$API_URL$ENDPOINT?test=1' OR '1'='1"
curl -s "$API_URL$ENDPOINT?test=../../etc/passwd"
echo ""

echo "5. Test TLS Fingerprinting"
echo "Vérification des fingerprints..."
curl -s -H "X-TLS-Version: TLSv1.3" -H "X-TLS-Cipher-Suites: TLS_AES_256_GCM_SHA384" "$API_URL$ENDPOINT"
echo ""

echo "Tests terminés. Vérifiez les logs et le dashboard pour les résultats."

