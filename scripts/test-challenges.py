import requests
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

API_URL = "http://localhost:8000"
ENDPOINT = "/api/test"

def test_cookie_challenge():
    print("=== Test Cookie Challenge ===")
    session = requests.Session()
    
    response = session.get(f"{API_URL}{ENDPOINT}")
    print(f"Status: {response.status_code}")
    
    if response.status_code == 429:
        print("Cookie challenge détecté!")
        challenge_data = response.json()
        print(f"Challenge: {challenge_data}")
        
        if "waf_challenge" in session.cookies:
            print("Cookie reçu, nouvelle requête...")
            response2 = session.get(f"{API_URL}{ENDPOINT}")
            print(f"Status après cookie: {response2.status_code}")
    else:
        print("Pas de challenge cookie")
    print()

def test_pow_challenge():
    print("=== Test Proof-of-Work Challenge ===")
    
    for i in range(10):
        response = requests.get(f"{API_URL}{ENDPOINT}")
        print(f"Requête {i+1}: Status {response.status_code}")
        
        if response.status_code == 429:
            try:
                challenge_data = response.json()
                if challenge_data.get("type") == "proof_of_work":
                    print(f"PoW Challenge détecté!")
                    print(f"Token: {challenge_data.get('token')}")
                    print(f"Difficulté: {challenge_data.get('difficulty')}")
                    print(f"JS Code disponible: {'js_code' in challenge_data}")
                    break
            except:
                pass
        time.sleep(0.1)
    print()

def test_rate_limit_escalation():
    print("=== Test Escalade Rate Limiting ===")
    
    responses = []
    for i in range(200):
        try:
            response = requests.get(f"{API_URL}{ENDPOINT}", timeout=2)
            responses.append(response.status_code)
        except:
            responses.append("timeout")
        
        if i % 20 == 0:
            status_counts = {}
            for status in responses[-20:]:
                status_counts[status] = status_counts.get(status, 0) + 1
            print(f"Requêtes {i-19}-{i}: {status_counts}")
    
    final_counts = {}
    for status in responses:
        final_counts[status] = final_counts.get(status, 0) + 1
    print(f"\nRésumé final: {final_counts}")
    print()

def test_tls_fingerprint():
    print("=== Test TLS Fingerprinting ===")
    
    headers = {
        "X-TLS-Version": "TLSv1.3",
        "X-TLS-Cipher-Suites": "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256",
        "X-TLS-Extensions": "server_name,extended_master_secret,key_share",
        "X-TLS-Curves": "X25519,P-256",
        "X-TLS-Point-Formats": "uncompressed"
    }
    
    response = requests.get(f"{API_URL}{ENDPOINT}", headers=headers)
    print(f"Status: {response.status_code}")
    
    fingerprint_info = requests.get(f"{API_URL}/api/tls-fingerprint/{hash('test')}")
    print(f"Fingerprint API: {fingerprint_info.status_code}")
    print()

def test_reputation_api():
    print("=== Test API Réputation ===")
    
    test_ip = "127.0.0.1"
    
    try:
        reputation = requests.get(f"{API_URL}/api/reputation/{test_ip}")
        print(f"Réputation IP {test_ip}: {reputation.status_code}")
        if reputation.status_code == 200:
            print(json.dumps(reputation.json(), indent=2))
    except Exception as e:
        print(f"Erreur: {e}")
    print()

def test_parallel_requests():
    print("=== Test Requêtes Parallèles (DDoS Simulation) ===")
    
    def make_request(i):
        try:
            response = requests.get(f"{API_URL}{ENDPOINT}", timeout=2)
            return (i, response.status_code)
        except Exception as e:
            return (i, f"error: {str(e)[:30]}")
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(make_request, i) for i in range(500)]
        results = [f.result() for f in as_completed(futures)]
    
    status_counts = {}
    for _, status in results:
        status_counts[status] = status_counts.get(status, 0) + 1
    
    print(f"Résultats: {status_counts}")
    print(f"Total: {len(results)} requêtes")
    print()

if __name__ == "__main__":
    print("=== Tests Anti-DDoS WAF ===\n")
    
    test_cookie_challenge()
    test_pow_challenge()
    test_rate_limit_escalation()
    test_tls_fingerprint()
    test_reputation_api()
    test_parallel_requests()
    
    print("=== Tests terminés ===")

