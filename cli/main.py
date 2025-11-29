import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align
from rich.prompt import Prompt, Confirm, IntPrompt
import time
import os
import sys
from pathlib import Path
from cli.menu import InteractiveMenu

console = Console()

def gradient_text(text: str):
    colors = [
        "#FFD700",
        "#FFE135",
        "#FFEB3B",
        "#FFC107",
        "#FFD54F",
        "#FFE082",
    ]
    
    gradient = Text()
    for i, char in enumerate(text):
        if char == " ":
            gradient.append(char)
            continue
        
        progress = i / max(len(text) - 1, 1)
        color_index = int(progress * (len(colors) - 1))
        color = colors[color_index]
        
        gradient.append(char, style=f"bold {color}")
    
    return gradient

def print_gradient_title(text: str):
    title = gradient_text(text)
    console.print(title)
    console.print()

def generate_nginx_config(rate_limit_requests: int, rate_limit_burst: int, ddos_max_connections: int):
    """Génère la configuration Nginx adaptée aux paramètres du WAF avec commentaires explicatifs"""
    rate_per_second = max(1, rate_limit_requests // 60)
    
    nginx_config = f"""events {{
    worker_connections 1024;
}}

http {{
    upstream waf_backend {{
        server waf-api:8000;
    }}

    limit_req_zone $binary_remote_addr zone=waf_limit:10m rate={rate_per_second}r/s;
    limit_conn_zone $binary_remote_addr zone=waf_conn_limit:10m;

    server {{
        listen 80;
        server_name _;

        limit_conn waf_conn_limit {ddos_max_connections};

        location / {{
            limit_req zone=waf_limit burst={rate_limit_burst} nodelay;
            proxy_pass http://waf_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }}
    }}
}}
"""
    return nginx_config

def print_banner():
    console.print()
    banner = gradient_text("PyWaf Client")
    console.print(banner)
    console.print()

def interactive_help():
    """Menu interactif pour sélectionner une commande"""
    while True:
        menu = InteractiveMenu(is_main_menu=True)
        menu.set_title("Commandes disponibles")
        menu.add_option("dev", "Démarrer le serveur en mode développement", lambda: "dev")
        menu.add_option("start", "Démarrer tous les services", lambda: "start")
        menu.add_option("stop", "Arrêter tous les services", lambda: "stop")
        menu.add_option("restart", "Redémarrer tous les services", lambda: "restart")
        menu.add_option("setup", "Configuration initiale du WAF", lambda: "setup")
        menu.add_option("exit", "Quitter", lambda: "exit")
        
        result = menu.run()
        
        if result == "exit":
            console.print("\n[dim]Au revoir![/dim]\n")
            break
        elif result == "dev":
            try:
                run_dev_server(port=8000, host="0.0.0.0", reload=True)
            except KeyboardInterrupt:
                console.print("\n[dim]Opération annulée[/dim]\n")
            break
        elif result == "start":
            try:
                start_services()
            except KeyboardInterrupt:
                console.print("\n[dim]Opération annulée[/dim]\n")
        elif result == "stop":
            try:
                stop_services()
            except KeyboardInterrupt:
                console.print("\n[dim]Opération annulée[/dim]\n")
        elif result == "restart":
            try:
                restart_services()
            except KeyboardInterrupt:
                console.print("\n[dim]Opération annulée[/dim]\n")
        elif result == "setup":
            try:
                setup_interactive()
            except KeyboardInterrupt:
                console.print("\n[dim]Opération annulée[/dim]\n")

app = typer.Typer(
    name="waf",
    help="PyWaf Client - Gestion de votre Web Application Firewall",
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode="rich",
    invoke_without_command=True
)

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        print_banner()
        interactive_help()
        raise typer.Exit()

def run_dev_server(port: int = 8000, host: str = "0.0.0.0", reload: bool = True):
    """Fonction interne pour démarrer le serveur en mode développement"""
    print_banner()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Démarrage du serveur WAF...", total=None)
        time.sleep(1.5)
    
    console.print("[bold green]OK[/bold green] Serveur démarré avec succès\n")
    
    info_table = Table(box=None, show_header=False, padding=(0, 2), show_lines=False)
    info_table.add_row("[dim]>[/dim] [bold]API:[/bold]", f"[cyan]http://localhost:{port}[/cyan]")
    info_table.add_row("[dim]>[/dim] [bold]Docs:[/bold]", f"[cyan]http://localhost:{port}/docs[/cyan]")
    info_table.add_row("[dim]>[/dim] [bold]Health:[/bold]", f"[cyan]http://localhost:{port}/health[/cyan]")
    
    console.print(Panel(info_table, border_style="cyan", padding=(1, 2)))
    console.print("\n[dim]Appuyez sur Ctrl+C pour arrêter[/dim]\n")
    
    import subprocess
    import sys
    
    cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", host, "--port", str(port)]
    if reload:
        cmd.append("--reload")
    
    try:
        subprocess.run(cmd, cwd=Path.cwd())
    except KeyboardInterrupt:
        console.print("\n[dim]Arrêt du serveur[/dim]\n")

@app.command()
def dev(
    port: int = typer.Option(8000, "--port", "-p", help="Port du serveur"),
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host du serveur"),
    reload: bool = typer.Option(True, "--reload/--no-reload", help="Activer le rechargement automatique")
):
    """Démarrer le serveur en mode développement"""
    run_dev_server(port=port, host=host, reload=reload)

@app.command()
def status():
    """Afficher le statut des services"""
    print_banner()
    
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Vérification des services...", total=None)
        time.sleep(0.8)
    
    try:
        result = subprocess.run(
            ["docker-compose", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
        
        if result.returncode == 0:
            import json
            services = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        services.append(json.loads(line))
                    except:
                        pass
            
            if services:
                table = Table(box=None, show_header=True, header_style="bold cyan", padding=(0, 2))
                table.add_column("Service", style="cyan", no_wrap=True)
                table.add_column("Status", justify="center", width=12)
                table.add_column("Ports", style="magenta")
                
                for service in services:
                    state = service.get("State", "unknown")
                    if state == "running":
                        status_icon = "[bold green]*[/bold green]"
                        status_text = "[green]Running[/green]"
                    else:
                        status_icon = "[bold red]*[/bold red]"
                        status_text = "[red]Stopped[/red]"
                    
                    ports = service.get("Publishers", [])
                    port_str = ", ".join([f"{p.get('PublishedPort', '')}:{p.get('TargetPort', '')}" for p in ports]) if ports else "[dim]-[/dim]"
                    
                    table.add_row(
                        service.get("Service", "unknown"),
                        f"{status_icon} {status_text}",
                        port_str
                    )
                
                console.print()
                console.print(table)
                console.print()
            else:
                console.print("[yellow]WARNING[/yellow] Aucun service en cours d'exécution\n")
        else:
            console.print("[bold red]ERROR[/bold red] Impossible de récupérer le statut des services")
            console.print("[dim]Assurez-vous que Docker est démarré[/dim]\n")
    except FileNotFoundError:
        console.print("[bold red]ERROR[/bold red] docker-compose n'est pas installé\n")
    except Exception as e:
        console.print(f"[bold red]ERROR[/bold red] Erreur: {str(e)}\n")

@app.command()
def logs(
    service: str = typer.Argument(None, help="Nom du service (waf-api, postgres, redis, celery-worker)"),
    tail: int = typer.Option(100, "--tail", "-n", help="Nombre de lignes à afficher")
):
    """Afficher les logs des services"""
    print_banner()
    
    import subprocess
    
    cmd = ["docker-compose", "logs", "--tail", str(tail)]
    if service:
        cmd.append(service)
    
    try:
        subprocess.run(cmd, cwd=Path.cwd())
    except FileNotFoundError:
        console.print("[bold red]ERROR[/bold red] docker-compose n'est pas installé\n")
    except KeyboardInterrupt:
        console.print("\n[dim]Arrêt du suivi des logs[/dim]\n")

@app.command()
def start():
    """Démarrer tous les services"""
    print_banner()
    
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Démarrage des services...", total=None)
        result = subprocess.run(
            ["docker-compose", "up", "-d"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
    
    if result.returncode == 0:
        console.print("[bold green]OK[/bold green] Services démarrés avec succès\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Attente que les services soient prêts...", total=None)
            time.sleep(3)
        
        console.print("[dim]>[/dim] Utilisez [bold cyan]waf status[/bold cyan] pour vérifier le statut\n")
    else:
        console.print("[bold red]ERROR[/bold red] Erreur lors du démarrage des services\n")
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]\n")

@app.command()
def stop():
    """Arrêter tous les services"""
    print_banner()
    
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Arrêt des services...", total=None)
        result = subprocess.run(
            ["docker-compose", "down"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
    
    if result.returncode == 0:
        console.print("[bold green]OK[/bold green] Services arrêtés avec succès\n")
    else:
        console.print("[bold red]ERROR[/bold red] Erreur lors de l'arrêt des services\n")
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]\n")

@app.command()
def restart():
    """Redémarrer tous les services"""
    print_banner()
    
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Redémarrage des services...", total=None)
        result = subprocess.run(
            ["docker-compose", "restart"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
    
    if result.returncode == 0:
        console.print("[bold green]OK[/bold green] Services redémarrés avec succès\n")
    else:
        console.print("[bold red]ERROR[/bold red] Erreur lors du redémarrage des services\n")
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]\n")

def setup_interactive():
    """Configuration interactive du WAF"""
    env_file = Path(".env")
    
    import secrets
    import string
    from urllib.parse import quote_plus
    import os
    
    postgres_password = None
    secret_key = None
    database_url = None
    redis_url = "redis://redis:6379/0"
    
    if env_file.exists():
        from dotenv import dotenv_values
        from urllib.parse import urlparse, unquote
        existing_env = dotenv_values(".env")
        
        postgres_password = existing_env.get("POSTGRES_PASSWORD")
        secret_key = existing_env.get("SECRET_KEY")
        database_url = existing_env.get("DATABASE_URL")
        redis_url = existing_env.get("REDIS_URL", "redis://redis:6379/0")
        
        if database_url and not postgres_password:
            parsed = urlparse(database_url)
            if parsed.password:
                postgres_password = unquote(parsed.password)
        
        if not postgres_password:
            postgres_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        if not secret_key:
            secret_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        if not database_url:
            encoded_password = quote_plus(postgres_password)
            database_url = f"postgresql://waf_user:{encoded_password}@postgres:5432/waf_db"
        
        print_gradient_title("Configuration complète du WAF")
        if existing_env.get("DATABASE_URL") and existing_env.get("POSTGRES_PASSWORD"):
            console.print("[dim]Configuration de la base de données : conservée depuis .env existant[/dim]\n")
        else:
            console.print("[dim]Configuration de la base de données : valeurs manquantes générées[/dim]\n")
        
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Le fichier .env existe déjà")
        menu.add_option("overwrite", "Mettre à jour la configuration WAF (conserve la DB)", lambda: "overwrite")
        menu.add_option("cancel", "Annuler", lambda: "back")
        menu.add_help_option()
        
        result = menu.run()
        if result == "cancel" or result == "exit" or result == "back" or result == "help":
            return "back"
    else:
        postgres_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        secret_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        encoded_password = quote_plus(postgres_password)
        database_url = f"postgresql://waf_user:{encoded_password}@postgres:5432/waf_db"
        
        print_gradient_title("Configuration complète du WAF")
        console.print("[dim]Configuration de la base de données : générée automatiquement[/dim]\n")
    
    encoded_password = quote_plus(postgres_password)
    
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Niveau de sensibilité SQL Injection")
    menu.add_option("high", "Élevé (recommandé)", lambda: "high")
    menu.add_option("medium", "Moyen", lambda: "medium")
    menu.add_option("low", "Faible", lambda: "low")
    menu.add_help_option()
    sql_sensitivity = menu.run()
    if sql_sensitivity == "back" or sql_sensitivity == "exit" or sql_sensitivity == "help":
        return "back"
    
    print_gradient_title("Protection SQL Injection")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer la protection SQL Injection")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    sql_enabled = menu.run()
    if sql_enabled == "back" or sql_enabled == "exit" or sql_enabled == "help":
        return "back"
    
    if sql_enabled == "true":
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Niveau de sensibilité SQL Injection")
        menu.add_option("high", "Élevé (recommandé)", lambda: "high")
        menu.add_option("medium", "Moyen", lambda: "medium")
        menu.add_option("low", "Faible", lambda: "low")
        menu.add_help_option()
        sql_sensitivity = menu.run()
        if sql_sensitivity == "back" or sql_sensitivity == "exit" or sql_sensitivity == "help":
            return "back"
    else:
        sql_sensitivity = "high"
    
    print_gradient_title("Protection XSS")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer la protection XSS")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    xss_enabled = menu.run()
    if xss_enabled == "back" or xss_enabled == "exit" or xss_enabled == "help":
        return "back"
    
    print_gradient_title("Rate Limiting")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer le rate limiting")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    rate_limiting_enabled = menu.run()
    if rate_limiting_enabled == "back" or rate_limiting_enabled == "exit" or rate_limiting_enabled == "help":
        return "back"
    
    rate_limit_requests = 100
    rate_limit_burst = 50
    rate_limit_by_ip = True
    
    if rate_limiting_enabled == "true":
        rate_limit_requests = IntPrompt.ask("Nombre de requêtes par minute", default=100)
        rate_limit_burst = IntPrompt.ask("Burst (requêtes supplémentaires autorisées)", default=rate_limit_requests // 2)
        
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Limiter par adresse IP")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        rate_limit_by_ip_str = menu.run()
        if rate_limit_by_ip_str == "back" or rate_limit_by_ip_str == "exit" or rate_limit_by_ip_str == "help":
            return "back"
        rate_limit_by_ip = rate_limit_by_ip_str == "true"
    
    print_gradient_title("Protection DDoS")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer la protection DDoS")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    ddos_enabled = menu.run()
    if ddos_enabled == "back" or ddos_enabled == "exit" or ddos_enabled == "help":
        return "back"
    
    ddos_max_connections = 50
    if ddos_enabled == "true":
        ddos_max_connections = IntPrompt.ask("Nombre maximum de connexions par IP", default=50)
    
    print_gradient_title("Réputation IP")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer la réputation IP")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    ip_reputation_enabled = menu.run()
    if ip_reputation_enabled == "back" or ip_reputation_enabled == "exit" or ip_reputation_enabled == "help":
        return "back"
    
    reputation_malicious = 70.0
    reputation_suspicious = 40.0
    if ip_reputation_enabled == "true":
        reputation_malicious = float(IntPrompt.ask("Seuil réputation malveillante (0-100)", default=70))
        reputation_suspicious = float(IntPrompt.ask("Seuil réputation suspecte (0-100)", default=40))
    
    print_gradient_title("Analyse comportementale")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer l'analyse comportementale")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    behavioral_analysis_enabled = menu.run()
    if behavioral_analysis_enabled == "back" or behavioral_analysis_enabled == "exit" or behavioral_analysis_enabled == "help":
        return "back"
    
    print_gradient_title("Rate Limiting Adaptatif")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer le rate limiting adaptatif")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    adaptive_rate_limiting_enabled = menu.run()
    if adaptive_rate_limiting_enabled == "back" or adaptive_rate_limiting_enabled == "exit" or adaptive_rate_limiting_enabled == "help":
        return "back"
    
    print_gradient_title("Système de Challenge")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer le système de challenge")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    challenge_system_enabled = menu.run()
    if challenge_system_enabled == "back" or challenge_system_enabled == "exit" or challenge_system_enabled == "help":
        return "back"
    
    pow_difficulty_min = 1
    pow_difficulty_max = 5
    challenge_bypass_threshold = 3
    if challenge_system_enabled == "true":
        pow_difficulty_min = IntPrompt.ask("Difficulté PoW minimale (1-10)", default=1)
        pow_difficulty_max = IntPrompt.ask("Difficulté PoW maximale (1-10)", default=5)
        challenge_bypass_threshold = IntPrompt.ask("Seuil de bypass du challenge", default=3)
    
    print_gradient_title("TLS Fingerprinting")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer le TLS Fingerprinting")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    tls_fingerprinting_enabled = menu.run()
    if tls_fingerprinting_enabled == "back" or tls_fingerprinting_enabled == "exit" or tls_fingerprinting_enabled == "help":
        return "back"
    
    print_gradient_title("Mitigation DDoS par étapes")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Activer la mitigation DDoS par étapes")
    menu.add_option("true", "Oui", lambda: "true")
    menu.add_option("false", "Non", lambda: "false")
    menu.add_help_option()
    staged_ddos_mitigation_enabled = menu.run()
    if staged_ddos_mitigation_enabled == "back" or staged_ddos_mitigation_enabled == "exit" or staged_ddos_mitigation_enabled == "help":
        return "back"
    
    print_gradient_title("Paramètres de performance")
    max_latency_ms = IntPrompt.ask("Latence maximale (ms)", default=50)
    max_memory_mb = IntPrompt.ask("Mémoire maximale (MB)", default=512)
    
    print_gradient_title("Environnement")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Environnement")
    menu.add_option("production", "Production", lambda: "production")
    menu.add_option("development", "Développement", lambda: "development")
    menu.add_help_option()
    environment = menu.run()
    if environment == "back" or environment == "exit" or environment == "help":
        return "back"
    
    print_gradient_title("Niveau de log")
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Niveau de log")
    menu.add_option("DEBUG", "DEBUG", lambda: "DEBUG")
    menu.add_option("INFO", "INFO (recommandé)", lambda: "INFO")
    menu.add_option("WARNING", "WARNING", lambda: "WARNING")
    menu.add_option("ERROR", "ERROR", lambda: "ERROR")
    menu.add_help_option()
    log_level = menu.run()
    if log_level == "back" or log_level == "exit" or log_level == "help":
        return "back"
    
    env_content = f"""DATABASE_URL={database_url}
REDIS_URL={redis_url}
SECRET_KEY={secret_key}
ENVIRONMENT={environment}
LOG_LEVEL={log_level}
POSTGRES_PASSWORD={postgres_password}

SQL_INJECTION_ENABLED={sql_enabled}
SQL_INJECTION_SENSITIVITY={sql_sensitivity}
XSS_PROTECTION_ENABLED={xss_enabled}

RATE_LIMITING_ENABLED={rate_limiting_enabled}
RATE_LIMIT_REQUESTS_PER_MINUTE={rate_limit_requests}
RATE_LIMIT_BURST={rate_limit_burst}
RATE_LIMIT_BY_IP={str(rate_limit_by_ip).lower()}

DDOS_PROTECTION_ENABLED={ddos_enabled}
DDOS_MAX_CONNECTIONS_PER_IP={ddos_max_connections}

IP_REPUTATION_ENABLED={ip_reputation_enabled}
REPUTATION_MALICIOUS_THRESHOLD={reputation_malicious}
REPUTATION_SUSPICIOUS_THRESHOLD={reputation_suspicious}

BEHAVIORAL_ANALYSIS_ENABLED={behavioral_analysis_enabled}
ADAPTIVE_RATE_LIMITING_ENABLED={adaptive_rate_limiting_enabled}
CHALLENGE_SYSTEM_ENABLED={challenge_system_enabled}
POW_CHALLENGE_DIFFICULTY_MIN={pow_difficulty_min}
POW_CHALLENGE_DIFFICULTY_MAX={pow_difficulty_max}
CHALLENGE_BYPASS_THRESHOLD={challenge_bypass_threshold}

TLS_FINGERPRINTING_ENABLED={tls_fingerprinting_enabled}
STAGED_DDOS_MITIGATION_ENABLED={staged_ddos_mitigation_enabled}

MAX_LATENCY_MS={max_latency_ms}
MAX_MEMORY_MB={max_memory_mb}
"""
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Création du fichier .env...", total=None)
        try:
            env_file.write_text(env_content, encoding='utf-8', errors='replace')
        except Exception as e:
            with open(env_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(env_content)
        time.sleep(0.8)
    
    console.print("\n[bold green]OK[/bold green] Fichier .env créé avec succès\n")
    console.print("[dim]Configuration complète sauvegardée dans .env[/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Génération de la configuration Nginx...", total=None)
        nginx_config = generate_nginx_config(rate_limit_requests, rate_limit_burst, ddos_max_connections)
        nginx_file = Path("nginx/nginx.conf")
        nginx_file.parent.mkdir(exist_ok=True)
        nginx_file.write_text(nginx_config, encoding='utf-8')
        time.sleep(0.5)
    
    console.print("[bold green]OK[/bold green] Configuration Nginx adaptée avec succès\n")
    console.print(f"[dim]Rate limiting: {rate_limit_requests} req/min ({max(1, rate_limit_requests // 60)} req/s), burst: {rate_limit_burst}[/dim]\n")
    console.print(f"[dim]Limite de connexions DDoS: {ddos_max_connections} connexions par IP[/dim]\n")
    
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Construction des images Docker")
    menu.add_option("yes", "Construire maintenant", lambda: "yes")
    menu.add_option("no", "Plus tard", lambda: "no")
    menu.add_help_option()
    
    build_choice = menu.run()
    if build_choice == "back" or build_choice == "exit" or build_choice == "help":
        return "back"
    
    if build_choice == "yes":
        import subprocess
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[yellow]Construction des images Docker...", total=None)
            result = subprocess.run(
                ["docker-compose", "build"],
                cwd=Path.cwd()
            )
        
        if result.returncode == 0:
            console.print("[bold green]OK[/bold green] Images construites avec succès\n")
        else:
            console.print("[bold red]ERROR[/bold red] Erreur lors de la construction des images\n")
    
    console.print("[dim]>[/dim] Utilisez [bold cyan]waf start[/bold cyan] pour démarrer les services\n")
    input("\nAppuyez sur Entrée pour continuer...")

@app.command()
def setup():
    """Configuration initiale du WAF"""
    print_banner()
    setup_interactive()

@app.command()
def metrics():
    """Afficher les métriques en temps réel"""
    print_banner()
    
    import httpx
    import json
    
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get("http://localhost:8000/metrics/overview?hours=24")
            if response.status_code == 200:
                data = response.json()
                
                table = Table(box=None, show_header=True, header_style="bold cyan", padding=(0, 2))
                table.add_column("Métrique", style="cyan")
                table.add_column("Valeur", style="green", justify="right")
                
                table.add_row("Requêtes totales", f"[bold]{data.get('total_requests', 0)}[/bold]")
                table.add_row("Requêtes bloquées", f"[bold red]{data.get('blocked_requests', 0)}[/bold red]")
                table.add_row("Taux de blocage", f"[bold yellow]{data.get('block_rate', 0):.2f}%[/bold yellow]")
                table.add_row("IPs uniques", f"[bold]{data.get('unique_ips', 0)}[/bold]")
                
                console.print()
                console.print(table)
                console.print()
            else:
                console.print("[bold red]ERROR[/bold red] Impossible de récupérer les métriques\n")
    except httpx.ConnectError:
        console.print("[bold red]ERROR[/bold red] Impossible de se connecter à l'API\n")
        console.print("[dim]Assurez-vous que le serveur est démarré avec [bold]waf dev[/bold] ou [bold]waf start[/bold][/dim]\n")
    except Exception as e:
        console.print(f"[bold red]ERROR[/bold red] Erreur: {str(e)}\n")

def start_services():
    """Démarrer les services (version pour menu)"""
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Démarrage des services...", total=None)
        result = subprocess.run(
            ["docker-compose", "up", "-d"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
    
    if result.returncode == 0:
        console.print("[bold green]OK[/bold green] Services démarrés avec succès\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Attente que les services soient prêts...", total=None)
            time.sleep(3)
        
        console.print("[dim]>[/dim] Utilisez [bold cyan]waf status[/bold cyan] pour vérifier le statut\n")
    else:
        console.print("[bold red]ERROR[/bold red] Erreur lors du démarrage des services\n")
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]\n")
    
    input("\nAppuyez sur Entrée pour continuer...")
    return "back"

def stop_services():
    """Arrêter les services (version pour menu)"""
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Arrêt des services...", total=None)
        result = subprocess.run(
            ["docker-compose", "down"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
    
    if result.returncode == 0:
        console.print("[bold green]OK[/bold green] Services arrêtés avec succès\n")
    else:
        console.print("[bold red]ERROR[/bold red] Erreur lors de l'arrêt des services\n")
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]\n")
    
    input("\nAppuyez sur Entrée pour continuer...")
    return "back"

def restart_services():
    """Redémarrer les services (version pour menu)"""
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Redémarrage des services...", total=None)
        result = subprocess.run(
            ["docker-compose", "restart"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
    
    if result.returncode == 0:
        console.print("[bold green]OK[/bold green] Services redémarrés avec succès\n")
    else:
        console.print("[bold red]ERROR[/bold red] Erreur lors du redémarrage des services\n")
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]\n")
    
    input("\nAppuyez sur Entrée pour continuer...")
    return "back"

def show_status():
    """Afficher le statut (version pour menu)"""
    import subprocess
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Vérification des services...", total=None)
        time.sleep(0.8)
    
    try:
        result = subprocess.run(
            ["docker-compose", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=Path.cwd()
        )
        
        if result.returncode == 0:
            import json
            services = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        services.append(json.loads(line))
                    except:
                        pass
            
            if services:
                table = Table(box=None, show_header=True, header_style="bold cyan", padding=(0, 2))
                table.add_column("Service", style="cyan", no_wrap=True)
                table.add_column("Status", justify="center", width=12)
                table.add_column("Ports", style="magenta")
                
                for service in services:
                    state = service.get("State", "unknown")
                    if state == "running":
                        status_icon = "[bold green]*[/bold green]"
                        status_text = "[green]Running[/green]"
                    else:
                        status_icon = "[bold red]*[/bold red]"
                        status_text = "[red]Stopped[/red]"
                    
                    ports = service.get("Publishers", [])
                    port_str = ", ".join([f"{p.get('PublishedPort', '')}:{p.get('TargetPort', '')}" for p in ports]) if ports else "[dim]-[/dim]"
                    
                    table.add_row(
                        service.get("Service", "unknown"),
                        f"{status_icon} {status_text}",
                        port_str
                    )
                
                console.print()
                console.print(table)
                console.print()
            else:
                console.print("[yellow]WARNING[/yellow] Aucun service en cours d'exécution\n")
        else:
            console.print("[bold red]ERROR[/bold red] Impossible de récupérer le statut des services")
            console.print("[dim]Assurez-vous que Docker est démarré[/dim]\n")
    except FileNotFoundError:
        console.print("[bold red]ERROR[/bold red] docker-compose n'est pas installé\n")
    except Exception as e:
        console.print(f"[bold red]ERROR[/bold red] Erreur: {str(e)}\n")
    
    input("\nAppuyez sur Entrée pour continuer...")
    return "back"

def show_metrics():
    """Afficher les métriques (version pour menu)"""
    import httpx
    
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get("http://localhost:8000/metrics/overview?hours=24")
            if response.status_code == 200:
                data = response.json()
                
                table = Table(box=None, show_header=True, header_style="bold cyan", padding=(0, 2))
                table.add_column("Métrique", style="cyan")
                table.add_column("Valeur", style="green", justify="right")
                
                table.add_row("Requêtes totales", f"[bold]{data.get('total_requests', 0)}[/bold]")
                table.add_row("Requêtes bloquées", f"[bold red]{data.get('blocked_requests', 0)}[/bold red]")
                table.add_row("Taux de blocage", f"[bold yellow]{data.get('block_rate', 0):.2f}%[/bold yellow]")
                table.add_row("IPs uniques", f"[bold]{data.get('unique_ips', 0)}[/bold]")
                
                console.print()
                console.print(table)
                console.print()
            else:
                console.print("[bold red]ERROR[/bold red] Impossible de récupérer les métriques\n")
    except httpx.ConnectError:
        console.print("[bold red]ERROR[/bold red] Impossible de se connecter à l'API\n")
        console.print("[dim]Assurez-vous que le serveur est démarré avec [bold]waf dev[/bold] ou [bold]waf start[/bold][/dim]\n")
    except Exception as e:
        console.print(f"[bold red]ERROR[/bold red] Erreur: {str(e)}\n")
    
    input("\nAppuyez sur Entrée pour continuer...")
    return "back"

def show_help():
    """Afficher l'aide et permettre de quitter"""
    console.print()
    help_text = """
[bold cyan]Aide PyWaf Client[/bold cyan]

[bold]Commandes disponibles:[/bold]
  • Configuration initiale : Configurez votre WAF pour la première fois
  • Démarrer les services : Lance tous les services Docker
  • Arrêter les services : Arrête tous les services Docker
  • Redémarrer les services : Redémarre tous les services Docker
  • Statut des services : Affiche l'état de tous les services
  • Voir les logs : Consultez les logs des services
  • Mode développement : Lance le serveur en mode développement
  • Métriques : Affiche les métriques du WAF

[bold]Navigation:[/bold]
  • Flèches ↑↓ : Naviguer dans le menu
  • Entrée : Sélectionner une option
  • Q : Quitter (menu principal) ou Retour (sous-menus)
  • Ctrl+C : Quitter immédiatement l'application
"""
    console.print(Panel(help_text.strip(), border_style="cyan", padding=(1, 2)))
    console.print()
    
    menu = InteractiveMenu(is_main_menu=True)
    menu.set_title("Que souhaitez-vous faire ?")
    menu.add_option("back", "Retour au menu principal", lambda: "back")
    menu.add_option("exit", "Quitter l'application", lambda: "exit")
    
    result = menu.run()
    return result

def logs_interactive():
    """Menu interactif pour les logs"""
    menu = InteractiveMenu(is_main_menu=False)
    menu.set_title("Sélectionner un service")
    menu.add_option("waf-api", "API WAF", lambda: "waf-api")
    menu.add_option("postgres", "PostgreSQL", lambda: "postgres")
    menu.add_option("redis", "Redis", lambda: "redis")
    menu.add_option("celery-worker", "Celery Worker", lambda: "celery-worker")
    menu.add_option("all", "Tous les services", lambda: "all")
    menu.add_help_option()
    
    service = menu.run()
    if service == "back" or service == "exit" or service == "help":
        return "back"
    
    import subprocess
    cmd = ["docker-compose", "logs", "--tail", "100"]
    if service != "all":
        cmd.append(service)
    
    try:
        subprocess.run(cmd, cwd=Path.cwd())
    except FileNotFoundError:
        console.print("[bold red]ERROR[/bold red] docker-compose n'est pas installé\n")
    except KeyboardInterrupt:
        pass
    
    input("\nAppuyez sur Entrée pour continuer...")
    return "back"

if __name__ == "__main__":
    app()

