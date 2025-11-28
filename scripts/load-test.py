import requests
import time
import threading
import statistics
from collections import defaultdict

API_URL = "http://localhost:8000"
ENDPOINT = "/api/test"

class LoadTester:
    def __init__(self, url, num_threads=10, requests_per_thread=100, delay=0.1):
        self.url = url
        self.num_threads = num_threads
        self.requests_per_thread = requests_per_thread
        self.delay = delay
        self.results = defaultdict(list)
        self.lock = threading.Lock()
        
    def worker(self, thread_id):
        for i in range(self.requests_per_thread):
            start_time = time.time()
            try:
                response = requests.get(self.url, timeout=5)
                elapsed = time.time() - start_time
                
                with self.lock:
                    self.results[response.status_code].append(elapsed)
                    
            except requests.exceptions.Timeout:
                elapsed = time.time() - start_time
                with self.lock:
                    self.results['timeout'].append(elapsed)
            except Exception as e:
                elapsed = time.time() - start_time
                with self.lock:
                    self.results[f'error: {type(e).__name__}'].append(elapsed)
            
            time.sleep(self.delay)
    
    def run(self):
        print(f"=== Load Test ===")
        print(f"URL: {self.url}")
        print(f"Threads: {self.num_threads}")
        print(f"Requests par thread: {self.requests_per_thread}")
        print(f"Total: {self.num_threads * self.requests_per_thread} requêtes")
        print(f"Delay: {self.delay}s\n")
        
        start_time = time.time()
        
        threads = []
        for i in range(self.num_threads):
            t = threading.Thread(target=self.worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        total_time = time.time() - start_time
        
        print("=== Résultats ===")
        print(f"Temps total: {total_time:.2f}s")
        print(f"Requêtes/seconde: {(self.num_threads * self.requests_per_thread) / total_time:.2f}\n")
        
        for status, times in sorted(self.results.items()):
            count = len(times)
            avg_time = statistics.mean(times) if times else 0
            median_time = statistics.median(times) if times else 0
            min_time = min(times) if times else 0
            max_time = max(times) if times else 0
            
            print(f"Status {status}:")
            print(f"  Count: {count}")
            print(f"  Avg: {avg_time*1000:.2f}ms")
            print(f"  Median: {median_time*1000:.2f}ms")
            print(f"  Min: {min_time*1000:.2f}ms")
            print(f"  Max: {max_time*1000:.2f}ms")
            print()

if __name__ == "__main__":
    print("Choisissez un scénario de test:")
    print("1. Test léger (10 threads, 10 req/thread)")
    print("2. Test moyen (20 threads, 50 req/thread)")
    print("3. Test lourd (50 threads, 100 req/thread)")
    print("4. Test DDoS (100 threads, 200 req/thread)")
    
    choice = input("Choix (1-4): ")
    
    scenarios = {
        "1": (10, 10, 0.1),
        "2": (20, 50, 0.05),
        "3": (50, 100, 0.01),
        "4": (100, 200, 0.0)
    }
    
    if choice in scenarios:
        threads, req_per_thread, delay = scenarios[choice]
        tester = LoadTester(f"{API_URL}{ENDPOINT}", threads, req_per_thread, delay)
        tester.run()
    else:
        print("Choix invalide")

