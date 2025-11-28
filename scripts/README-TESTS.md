# Guide de Test Anti-DDoS

Ce guide vous permet de tester toutes les fonctionnalités anti-DDoS du WAF en local.

## Prérequis

1. **Docker et services démarrés** :
   ```powershell
   docker-compose up -d
   ```

2. **Vérifier que l'API est accessible** :
   ```powershell
   curl http://localhost:8000/health
   ```

3. **Installer les dépendances Python** (pour les scripts Python) :
   ```powershell
   pip install requests
   ```

## Méthodes de Test

### 1. Script PowerShell (Windows)

```powershell
.\scripts\test-ddos.ps1
```

**Ce que ça teste** :
- Rate limiting basique (150 requêtes)
- Burst limiting (60 requêtes simultanées)
- Détection User-Agent suspect
- Détection de patterns malveillants
- TLS Fingerprinting

### 2. Script Python - Tests Complets

```powershell
python scripts/test-challenges.py
```

**Ce que ça teste** :
- Cookie Challenge
- Proof-of-Work Challenge
- Escalade de rate limiting
- TLS Fingerprinting
- API de réputation
- Requêtes parallèles (simulation DDoS)

### 3. Load Testing Avancé

```powershell
python scripts/load-test.py
```

**Scénarios disponibles** :
1. Test léger : 10 threads, 10 requêtes/thread
2. Test moyen : 20 threads, 50 requêtes/thread
3. Test lourd : 50 threads, 100 requêtes/thread
4. Test DDoS : 100 threads, 200 requêtes/thread

### 4. Tests Manuels avec cURL

#### Test Rate Limiting
```powershell
# Envoi de 150 requêtes rapides
1..150 | ForEach-Object { curl http://localhost:8000/api/test }
```

#### Test Cookie Challenge
```powershell
# Première requête (devrait déclencher challenge)
curl -v http://localhost:8000/api/test

# Avec cookie (si challenge reçu)
curl -v -H "Cookie: waf_challenge=TOKEN" http://localhost:8000/api/test
```

#### Test TLS Fingerprinting
```powershell
curl -H "X-TLS-Version: TLSv1.3" `
     -H "X-TLS-Cipher-Suites: TLS_AES_256_GCM_SHA384" `
     -H "X-TLS-Extensions: server_name,extended_master_secret" `
     http://localhost:8000/api/test
```

#### Test avec Payloads Malveillants
```powershell
# XSS
curl "http://localhost:8000/api/test?q=<script>alert(1)</script>"

# SQL Injection
curl "http://localhost:8000/api/test?q=1' OR '1'='1"

# Path Traversal
curl "http://localhost:8000/api/test?q=../../etc/passwd"
```

### 5. Tests avec Apache Bench (ab)

Si vous avez Apache Bench installé :

```powershell
# Test basique (1000 requêtes, 10 simultanées)
ab -n 1000 -c 10 http://localhost:8000/api/test

# Test agressif (10000 requêtes, 100 simultanées)
ab -n 10000 -c 100 http://localhost:8000/api/test
```

### 6. Tests avec wrk (plus performant)

Si vous avez wrk installé :

```powershell
# Test 30 secondes, 10 threads, 100 connexions
wrk -t10 -c100 -d30s http://localhost:8000/api/test
```

## Vérification des Résultats

### 1. Dashboard Web

Accédez au dashboard :
```
http://localhost:3000
```

Vérifiez :
- Métriques de trafic
- Événements de sécurité bloqués
- Top IPs attaquantes
- Graphiques de distribution des menaces

### 2. API Endpoints de Monitoring

#### Vérifier les événements de sécurité
```powershell
curl http://localhost:8000/api/security/events?limit=10
```

#### Vérifier les statistiques
```powershell
curl http://localhost:8000/api/security/events/stats?hours=1
```

#### Vérifier la réputation d'une IP
```powershell
curl http://localhost:8000/api/reputation/127.0.0.1
```

#### Vérifier les fingerprints TLS
```powershell
curl http://localhost:8000/api/tls-fingerprint
```

### 3. Logs Docker

```powershell
# Logs de l'API
docker-compose logs -f waf-api

# Filtrer les logs de blocage
docker-compose logs waf-api | Select-String "blocked"
```

## Scénarios de Test Spécifiques

### Scénario 1 : Test d'Escalade de Challenges

1. Envoyez 20 requêtes normales → Devrait passer
2. Envoyez 50 requêtes rapides → Devrait déclencher Cookie Challenge
3. Contournez le cookie challenge 3 fois → Devrait escalader vers PoW
4. Contournez le PoW → Devrait bloquer complètement

### Scénario 2 : Test de Réputation IP

1. Envoyez des requêtes normales depuis une IP
2. Envoyez des requêtes avec payloads malveillants
3. Vérifiez que le score de réputation augmente
4. Vérifiez que les limites adaptatives se resserrent

### Scénario 3 : Test TLS Fingerprinting

1. Envoyez des requêtes avec différents fingerprints TLS
2. Whitelist un fingerprint légitime
3. Blacklist un fingerprint suspect
4. Vérifiez que les décisions sont appliquées

### Scénario 4 : Test DDoS Distribué

1. Simulez des requêtes depuis plusieurs IPs différentes
2. Utilisez différents User-Agents
3. Variez les patterns de requêtes
4. Vérifiez que le système détecte et bloque

## Interprétation des Résultats

### Codes de Statut Attendus

- **200 OK** : Requête autorisée
- **403 Forbidden** : Requête bloquée (IP blacklistée, fingerprint blacklisté, menace détectée)
- **429 Too Many Requests** : Rate limit dépassé ou challenge requis
- **500 Internal Server Error** : Erreur serveur (vérifier les logs)

### Métriques à Surveiller

1. **Taux de blocage** : Devrait augmenter avec les attaques
2. **Latence** : Devrait rester < 50ms pour requêtes légitimes
3. **Faux positifs** : Devrait être < 0.1%
4. **Escalade de challenges** : Devrait se produire automatiquement

## Dépannage

### Le conteneur ne démarre pas
```powershell
docker-compose logs waf-api
docker-compose restart waf-api
```

### Les migrations ne passent pas
```powershell
docker-compose exec waf-api alembic current
docker-compose exec waf-api alembic upgrade head
```

### L'API ne répond pas
```powershell
# Vérifier que le conteneur tourne
docker-compose ps

# Vérifier les logs
docker-compose logs -f waf-api

# Redémarrer
docker-compose restart waf-api
```

## Outils Recommandés

1. **Postman** : Pour tester les API endpoints manuellement
2. **Apache Bench (ab)** : Pour load testing simple
3. **wrk** : Pour load testing avancé
4. **Burp Suite** : Pour tests de sécurité avancés
5. **OWASP ZAP** : Pour tests de vulnérabilités

## Notes Importantes

- Les tests en local peuvent ne pas refléter exactement le comportement en production
- Ajustez les seuils dans `.env` selon vos besoins
- Surveillez les ressources système pendant les tests
- Les tests DDoS peuvent consommer beaucoup de ressources

