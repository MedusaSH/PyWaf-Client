<div align="center">

# 🛡️ PyWaf Client

**Protection avancée multi-couches pour vos applications web**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

**Détection intelligente • Protection DDoS • CLI interactif**

</div>

---

## 🌟 Vue d'ensemble

PyWaf Client est un Web Application Firewall moderne qui protège vos applications contre les cyberattaques. Avec une architecture multi-couches, une analyse comportementale avancée et un système de protection DDoS adaptatif.

**Fonctionnalités principales** :
- 🛡️ Protection SQL Injection, XSS, Command Injection, Path Traversal
- 🚨 Protection DDoS multi-niveaux avec escalade automatique
- 🧠 Machine Learning pour détection d'anomalies
- 📊 Réputation IP en temps réel
- 🔒 TLS Fingerprinting
- ⚡ Rate limiting adaptatif
- 🎯 Configuration complète via CLI interactif avec option "skip" pour configuration rapide

**Nouvelles fonctionnalités avancées** :
- 🧩 **Challenges de nouvelle génération** : JavaScript Tarpitting, détection headless browsers, cookies cryptographiques
- 🛡️ **Protection DDoS avancée** : SYN Cookie, protection table d'état, filtrage géographique dynamique
- 📈 **Analyse comportementale** : métriques par connexion (erreurs HTTP, low-and-slow, régularité temporelle)
- 🎯 **Score de malice comportemental** : agrégation multi-facteurs avec atténuation granulaire

---

## 🚀 Installation Complète de A à Z

### Prérequis

- **Docker Desktop** (Windows/Mac) ou **Docker** (Linux)
- **Python 3.11+**
- **Git** (optionnel)

### Étape 1 : Cloner le projet

```bash
git clone <url-du-repository>
cd WAF-main
```

### Étape 2 : Configuration interactive

Lancez le CLI pour configurer automatiquement tout le WAF :

```bash
python waf.py setup
```

Le CLI vous guide à travers :
- Génération automatique des clés de sécurité
- Configuration des protections (SQL Injection, XSS, DDoS, etc.)
- Paramètres de rate limiting (personnalisables)
- Configuration de la réputation IP
- **Option "skip"** : passer toutes les étapes suivantes avec valeurs par défaut
- Paramètres de performance
- Construction des images Docker

### Étape 3 : Démarrer les services

```bash
python waf.py start
```

Vérifier que tout fonctionne :

```bash
python waf.py status
```

### Étape 4 : Configuration Nginx sur votre serveur (Production)

Cette étape explique comment configurer Nginx sur votre serveur Linux pour protéger votre site web avec le WAF.

#### 4.1 Installer Nginx (si pas déjà installé)

**Ubuntu/Debian** :
```bash
sudo apt update
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

**CentOS/RHEL** :
```bash
sudo yum install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

#### 4.2 Configuration de base dans /etc/nginx/

Éditez le fichier principal de configuration :

```bash
sudo nano /etc/nginx/nginx.conf
```

Ajoutez la zone de rate limiting dans le bloc `http` :

```nginx
http {
    # ... autres configurations existantes ...
    
    # Zone de rate limiting pour le WAF
    limit_req_zone $binary_remote_addr zone=waf_limit:10m rate=100r/s;
    
    # ... reste de la configuration ...
}
```

#### 4.3 Créer/modifier la configuration de votre site

Créez ou modifiez le fichier de configuration de votre site dans `/etc/nginx/sites-available/` :

```bash
sudo nano /etc/nginx/sites-available/votre-site
```

**Configuration HTTP (port 80)** :

```nginx
server {
    listen 80;
    server_name votre-domaine.com www.votre-domaine.com;

    # Rate limiting WAF
    limit_req zone=waf_limit burst=50 nodelay;

    # Proxy vers le WAF qui protège votre application
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
    }
}
```

**Configuration HTTPS (port 443)** :

```nginx
server {
    listen 443 ssl http2;
    server_name votre-domaine.com www.votre-domaine.com;

    # Certificats SSL (Let's Encrypt ou autres)
    ssl_certificate /etc/letsencrypt/live/votre-domaine.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/votre-domaine.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Rate limiting WAF
    limit_req zone=waf_limit burst=50 nodelay;

    # Proxy vers le WAF
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
    }
}

# Redirection HTTP vers HTTPS
server {
    listen 80;
    server_name votre-domaine.com www.votre-domaine.com;
    return 301 https://$server_name$request_uri;
}
```

#### 4.4 Activer la configuration

**Ubuntu/Debian** :
```bash
# Créer le lien symbolique
sudo ln -s /etc/nginx/sites-available/votre-site /etc/nginx/sites-enabled/

# Tester la configuration
sudo nginx -t

# Recharger Nginx
sudo systemctl reload nginx
```

**CentOS/RHEL** :
```bash
# Copier la configuration
sudo cp /etc/nginx/sites-available/votre-site /etc/nginx/conf.d/votre-site.conf

# Tester la configuration
sudo nginx -t

# Recharger Nginx
sudo systemctl reload nginx
```

#### 4.5 Si vous avez déjà un site configuré

Si vous avez déjà une configuration Nginx pour votre site, modifiez simplement le bloc `location /` :

**Avant** (configuration directe vers votre app) :
```nginx
location / {
    proxy_pass http://127.0.0.1:3000;  # Votre application
}
```

**Après** (avec protection WAF) :
```nginx
location / {
    limit_req zone=waf_limit burst=50 nodelay;
    proxy_pass http://127.0.0.1:8000;  # WAF qui protège votre app
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

#### 4.6 Vérifier que tout fonctionne

```bash
# Vérifier le statut de Nginx
sudo systemctl status nginx

# Vérifier que le WAF écoute sur le port 8000
curl http://localhost:8000/health

# Tester depuis l'extérieur
curl http://votre-domaine.com
```

### Étape 5 : Vérification finale

1. **Tester l'API** : http://localhost:8000/docs
2. **Tester Nginx** : http://localhost (ou https://localhost si HTTPS configuré)
3. **Vérifier les logs** : `python waf.py logs waf-api`

---

## 💻 CLI Interactif

### Menu principal

Lancez simplement :

```bash
python waf.py
```

Navigation par flèches dans un menu interactif.

### Commandes disponibles

```bash
# Configuration interactive complète
python waf.py setup

# Mode développement avec rechargement auto
python waf.py dev

# Gestion des services Docker
python waf.py start      # Démarrer tous les services
python waf.py stop       # Arrêter tous les services
python waf.py restart    # Redémarrer tous les services

# Monitoring
python waf.py status     # Statut détaillé des services
python waf.py logs <service>  # Logs d'un service
python waf.py metrics    # Métriques en temps réel
```

---

## 📊 Architecture

```
Client → Nginx (Rate Limiting + SYN Cookie) → WAF Middleware → WAF Engine
                                                      ↓
                    ┌─────────────────────────────────┴─────────────────────────────────┐
                    │                                                                   │
            ┌───────▼────────┐  ┌──────────────┐  ┌──────────────────┐  ┌─────────────┐
            │ IP Manager     │→ │ Rate Limiter │→ │ Threat Detector  │→ │ Geo Filter  │
            │ (Whitelist/    │  │ (Burst/Min)  │  │ (SQLi/XSS/etc)   │  │ (Dynamic)   │
            │  Blacklist)    │  └──────────────┘  └──────────────────┘  └─────────────┘
            └────────────────┘
                    │
            ┌───────▼────────┐  ┌──────────────┐  ┌──────────────────┐  ┌─────────────┐
            │ Reputation     │→ │ Behavioral   │→ │ Challenge        │→ │ Connection  │
            │ Engine         │  │ Analyzer     │  │ System (PoW/     │  │ State Prot. │
            │                │  │              │  │  Tarpit/Cookie)  │  │             │
            └────────────────┘  └──────────────┘  └──────────────────┘  └─────────────┘
                    │                   │
            ┌───────▼────────┐  ┌───────▼────────┐
            │ Malice Scorer  │→ │ Headless       │
            │ (Multi-factor) │  │ Detector       │
            └────────────────┘  └────────────────┘
                    │
            ┌───────▼────────┐
            │ PostgreSQL     │  Redis (Cache + Metrics)
            │ (Logs/Rules)   │  (Rate Limiting + Connection Metrics)
            └────────────────┘
```

---

## 🚀 Nouvelles Fonctionnalités Avancées

### Challenges de Nouvelle Génération
- **JavaScript Tarpitting** : Puzzle client-side CPU-intensif pour ralentir les bots
- **Détection Headless Browsers** : Identification automatique de Puppeteer, Selenium, Playwright
- **Cookies Cryptographiques** : Challenge first-party avec cookie chiffré pour preuve de légitimité

### Protection DDoS Avancée
- **SYN Cookie** : Validation TCP handshake sans stocker l'état complet (décharge le WAF)
- **Protection Table d'État** : Surveillance et limitation des connexions semi-ouvertes
- **Filtrage Géographique Dynamique** : Blocage temporaire de régions identifiées comme sources d'attaque

### Analyse Comportementale Avancée
- **Métriques par Connexion** : Taux d'erreur HTTP, détection low-and-slow, régularité temporelle
- **Score de Malice Comportemental** : Agrégation multi-facteurs (erreurs, timing, réputation IP, TLS fingerprinting)
- **Atténuation Granulaire** : Tarpitting → Challenges difficiles → Blocage selon le score de malice

### CLI Amélioré
- **Option "skip"** : Configuration rapide avec valeurs par défaut pour toutes les étapes suivantes
- **Navigation simplifiée** : Bouton retour uniquement au menu de configuration rapide

---

## 🔧 Configuration

Tous les paramètres sont configurables via le CLI `waf.py setup` ou directement dans `.env` :

```env
# Protections
SQL_INJECTION_ENABLED=true
SQL_INJECTION_SENSITIVITY=high
XSS_PROTECTION_ENABLED=true

# Rate Limiting
RATE_LIMITING_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100
RATE_LIMIT_BURST=50

# Protection DDoS
DDOS_PROTECTION_ENABLED=true
DDOS_MAX_CONNECTIONS_PER_IP=50

# Réputation IP
IP_REPUTATION_ENABLED=true
REPUTATION_MALICIOUS_THRESHOLD=70.0

# Challenges
CHALLENGE_SYSTEM_ENABLED=true
POW_CHALLENGE_DIFFICULTY_MIN=1
POW_CHALLENGE_DIFFICULTY_MAX=5
HEADLESS_DETECTION_ENABLED=true
JAVASCRIPT_TARPIT_ENABLED=true
ENCRYPTED_COOKIE_CHALLENGE_ENABLED=true

# Protection DDoS avancée
SYN_COOKIE_ENABLED=true
CONNECTION_STATE_PROTECTION_ENABLED=true
GEO_FILTERING_ENABLED=false

# Analyse comportementale
CONNECTION_METRICS_ENABLED=true
BEHAVIORAL_MALICE_SCORING_ENABLED=true

# TLS Fingerprinting
TLS_FINGERPRINTING_ENABLED=true
STAGED_DDOS_MITIGATION_ENABLED=true
```

---

## 📚 API REST

Documentation interactive : http://localhost:8000/docs

**Endpoints principaux** :
- `GET /api/security/events` - Événements de sécurité
- `POST /api/rules/whitelist` - Ajouter IP à whitelist
- `POST /api/rules/blacklist` - Ajouter IP à blacklist
- `GET /api/metrics/overview` - Métriques en temps réel
- `GET /api/logs/security` - Logs de sécurité
- `POST /api/challenges/verify-tarpit` - Vérification challenge JavaScript Tarpit
- `POST /api/challenges/verify-encrypted-cookie` - Vérification cookie cryptographique
- `GET /api/geo-filtering/status` - Statut filtrage géographique
- `POST /api/geo-filtering/block-region` - Bloquer une région
- `GET /api/connection-metrics/{ip}` - Métriques de connexion par IP

---

## 🐛 Dépannage

### Erreur : "error during connect" ou "Cannot connect to the Docker daemon"

**Cause :** Cette erreur survient lorsque Docker Desktop n'est pas démarré ou que le daemon Docker n'est pas accessible.

**Symptômes :**
- Message d'erreur : `error during connect: Get "http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/v1.51/...": open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified`
- Message d'erreur : `Cannot connect to the Docker daemon at unix:///var/run/docker.sock`
- Message d'erreur : `unable to get image 'postgres:15-alpine': error during connect`

**Solutions :**

**Windows :**
1. Ouvrez Docker Desktop depuis le menu Démarrer
2. Attendez que Docker Desktop soit complètement démarré (icône Docker dans la barre des tâches)
3. Vérifiez que Docker Desktop est en cours d'exécution : `docker info`
4. Réessayez la commande : `python waf.py start`

**Linux :**
```bash
# Démarrer le service Docker
sudo systemctl start docker

# Vérifier le statut
sudo systemctl status docker

# Activer Docker au démarrage (optionnel)
sudo systemctl enable docker
```

**Mac :**
1. Ouvrez Docker Desktop depuis Applications
2. Attendez que l'icône Docker dans la barre de menu soit verte
3. Vérifiez : `docker info`

**Vérification rapide :**
```bash
# Vérifier si Docker est accessible
docker info

# Si l'erreur persiste, redémarrez Docker Desktop
```

**Note :** Le CLI vérifie maintenant automatiquement si Docker est disponible avant de lancer les services et affiche un message d'erreur explicite si Docker n'est pas démarré.

### Port déjà utilisé

**Windows** :
```powershell
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

**Linux** :
```bash
sudo lsof -i :8000
sudo kill -9 <PID>
```

### Erreur de connexion à la base de données

```bash
docker-compose ps postgres
docker-compose exec postgres psql -U waf_user -d waf_db
```

### Nginx ne démarre pas

```bash
# Vérifier la configuration
docker-compose exec nginx nginx -t

# Voir les logs
docker-compose logs nginx
```

---

## 📈 Performance

- **Latence** : < 50ms
- **Throughput** : 10,000 req/s
- **Mémoire** : < 512MB
- **Démarrage** : < 5s

---

## 🔒 Sécurité

- Validation stricte de toutes les entrées
- Pas de secrets dans le code
- Logging structuré sans données sensibles
- Principe de moindre privilège
- Fail-open pour disponibilité maximale

---

## 📄 Licence

Propriétaire - Tous droits réservés

---

<div align="center">

**Fait avec ❤️ pour sécuriser le web**

</div>
