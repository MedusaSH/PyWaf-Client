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

def generate_nginx_config(rate_limit_requests: int, rate_limit_burst: int, ddos_max_connections: int, syn_cookie_enabled: str = "true"):
    """Génère la configuration Nginx adaptée aux paramètres du WAF avec commentaires explicatifs"""
    rate_per_second = max(1, rate_limit_requests // 60)
    
    syn_cookie_directive = ""
    if syn_cookie_enabled == "true":
        syn_cookie_directive = """
    # Protection SYN Cookie activée
    # Note: SYN cookie est géré au niveau du kernel Linux
    # Pour activer: sysctl -w net.ipv4.tcp_syncookies=1
    # Cette directive est documentée ici pour référence"""
    
    nginx_config = f"""events {{
    worker_connections 1024;
    # Utilise epoll pour de meilleures performances
    use epoll;
}}

http {{
    upstream waf_backend {{
        server waf-api:8000;
        keepalive 32;
    }}

    limit_req_zone $binary_remote_addr zone=waf_limit:10m rate={rate_per_second}r/s;
    limit_conn_zone $binary_remote_addr zone=waf_conn_limit:10m;
    
    # Protection contre l'épuisement de la table d'état
    limit_conn_zone $binary_remote_addr zone=conn_state_limit:10m;
{syn_cookie_directive}
    server {{
        listen 80;
        server_name _;

        # Limite les connexions par IP
        limit_conn waf_conn_limit {ddos_max_connections};
        
        # Protection supplémentaire contre les connexions simultanées
        limit_conn conn_state_limit 50;

        location / {{
            limit_req zone=waf_limit burst={rate_limit_burst} nodelay;
            
            proxy_pass http://waf_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            
            # Timeouts pour éviter l'épuisement des ressources
            proxy_connect_timeout 10s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
            
            # Keep-alive pour améliorer les performances
            proxy_http_version 1.1;
            proxy_set_header Connection "";
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
                setup_result = setup_interactive()
                # Si setup_interactive retourne "back", on revient au menu principal
                if setup_result == "back":
                    continue
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
    """Configuration interactive du WAF avec navigation par étapes"""
    env_file = Path(".env")
    
    import secrets
    import string
    from urllib.parse import quote_plus
    import os
    
    postgres_password = None
    secret_key = None
    database_url = None
    redis_url = "redis://redis:6379/0"
    current_step = 0
    
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
        
        while True:
            menu = InteractiveMenu(is_main_menu=False)
            menu.set_title("Le fichier .env existe déjà")
            menu.add_option("overwrite", "Mettre à jour la configuration WAF (conserve la DB)", lambda: "overwrite")
            menu.add_option("cancel", "Annuler", lambda: "back")
            menu.add_help_option()
            
            result = menu.run()
            if result == "cancel" or result == "exit" or result == "help" or result == "back_step":
                return "back"
            elif result == "overwrite":
                break
    else:
        postgres_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        secret_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        encoded_password = quote_plus(postgres_password)
        database_url = f"postgresql://waf_user:{encoded_password}@postgres:5432/waf_db"
        
        print_gradient_title("Configuration complète du WAF")
        console.print("[dim]Configuration de la base de données : générée automatiquement[/dim]\n")
    
    encoded_password = quote_plus(postgres_password)
    
    step_stack = []
    
    def run_menu_step(step_func, step_name=None):
        if step_name:
            step_stack.append(step_name)
        while True:
            result = step_func()
            if result == "back_step":
                if step_stack:
                    step_stack.pop()
                return "back_step"
            elif result == "back" or result == "exit" or result == "help":
                if step_stack:
                    step_stack.pop()
                return result
            else:
                return result
    
    def handle_back_step(result, prev_step_func, prev_step_name=None):
        if result == "back_step":
            if prev_step_func:
                prev_result = run_menu_step(prev_step_func, prev_step_name)
                if prev_result == "back_step":
                    return "back_step"
                elif prev_result == "back" or prev_result == "exit" or prev_result == "help":
                    return prev_result
                result = run_menu_step(lambda: result, None)
                if result == "back_step" or result == "back" or result == "exit" or result == "help":
                    return result
            else:
                return "back"
        return result
    
    def step_sql_enabled():
        print_gradient_title("Protection SQL Injection")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer la protection SQL Injection")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        return menu.run()
    
    sql_enabled = run_menu_step(step_sql_enabled, "sql_enabled")
    if sql_enabled == "back_step":
        return "back"
    if sql_enabled == "back" or sql_enabled == "exit" or sql_enabled == "help":
        return "back"
    
    if sql_enabled == "true":
        def step_sql_sensitivity():
            menu = InteractiveMenu(is_main_menu=False)
            menu.set_title("Niveau de sensibilité SQL Injection")
            menu.add_option("high", "Élevé (recommandé)", lambda: "high")
            menu.add_option("medium", "Moyen", lambda: "medium")
            menu.add_option("low", "Faible", lambda: "low")
            menu.add_help_option()
            return menu.run()
        
        sql_sensitivity = run_menu_step(step_sql_sensitivity, "sql_sensitivity")
        if sql_sensitivity == "back_step":
            sql_enabled = run_menu_step(step_sql_enabled, "sql_enabled")
            if sql_enabled == "back_step":
                return "back"
            if sql_enabled == "back" or sql_enabled == "exit" or sql_enabled == "help":
                return "back"
            if sql_enabled == "true":
                sql_sensitivity = run_menu_step(step_sql_sensitivity, "sql_sensitivity")
                if sql_sensitivity == "back_step" or sql_sensitivity == "back" or sql_sensitivity == "exit" or sql_sensitivity == "help":
                    return "back"
        elif sql_sensitivity == "back" or sql_sensitivity == "exit" or sql_sensitivity == "help":
            return "back"
    else:
        sql_sensitivity = "high"
    
    def step_xss_enabled():
        print_gradient_title("Protection XSS")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer la protection XSS")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        return menu.run()
    
    xss_enabled = run_menu_step(step_xss_enabled, "xss_enabled")
    if xss_enabled == "back_step":
        if sql_enabled == "true":
            sql_sensitivity = run_menu_step(step_sql_sensitivity, "sql_sensitivity")
            if sql_sensitivity == "back_step":
                sql_enabled = run_menu_step(step_sql_enabled, "sql_enabled")
                if sql_enabled == "back_step":
                    return "back"
                if sql_enabled == "back" or sql_enabled == "exit" or sql_enabled == "help":
                    return "back"
                if sql_enabled == "true":
                    sql_sensitivity = run_menu_step(step_sql_sensitivity, "sql_sensitivity")
                    if sql_sensitivity == "back_step" or sql_sensitivity == "back" or sql_sensitivity == "exit" or sql_sensitivity == "help":
                        return "back"
            elif sql_sensitivity == "back" or sql_sensitivity == "exit" or sql_sensitivity == "help":
                return "back"
        xss_enabled = run_menu_step(step_xss_enabled, "xss_enabled")
        if xss_enabled == "back_step" or xss_enabled == "back" or xss_enabled == "exit" or xss_enabled == "help":
            return "back"
    elif xss_enabled == "back" or xss_enabled == "exit" or xss_enabled == "help":
        return "back"
    
    def step_rate_limiting():
        print_gradient_title("Rate Limiting")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer le rate limiting")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        return menu.run()
    
    rate_limiting_enabled = run_menu_step(step_rate_limiting, "rate_limiting")
    if rate_limiting_enabled == "back_step":
        xss_enabled = run_menu_step(step_xss_enabled, "xss_enabled")
        if xss_enabled == "back_step" or xss_enabled == "back" or xss_enabled == "exit" or xss_enabled == "help":
            return "back"
        rate_limiting_enabled = run_menu_step(step_rate_limiting, "rate_limiting")
        if rate_limiting_enabled == "back_step" or rate_limiting_enabled == "back" or rate_limiting_enabled == "exit" or rate_limiting_enabled == "help":
            return "back"
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
    headless_detection_enabled = "true"
    headless_detection_confidence_threshold = 0.6
    javascript_tarpit_enabled = "true"
    javascript_tarpit_complexity_min = 4
    javascript_tarpit_complexity_max = 7
    javascript_tarpit_min_solve_time_ms = 100.0
    javascript_tarpit_max_solve_time_ms = 30000.0
    encrypted_cookie_challenge_enabled = "true"
    encrypted_cookie_ttl = 3600
    
    if challenge_system_enabled == "true":
        pow_difficulty_min = IntPrompt.ask("Difficulté PoW minimale (1-10)", default=1)
        pow_difficulty_max = IntPrompt.ask("Difficulté PoW maximale (1-10)", default=5)
        challenge_bypass_threshold = IntPrompt.ask("Seuil de bypass du challenge", default=3)
        
        print_gradient_title("Détection Headless")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer la détection des navigateurs headless")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        headless_detection_enabled = menu.run()
        if headless_detection_enabled == "back" or headless_detection_enabled == "exit" or headless_detection_enabled == "help":
            return "back"
        
        if headless_detection_enabled == "true":
            headless_threshold_str = Prompt.ask("Seuil de confiance détection headless (0.0-1.0)", default="0.6")
            try:
                headless_detection_confidence_threshold = float(headless_threshold_str)
            except ValueError:
                headless_detection_confidence_threshold = 0.6
        
        print_gradient_title("Challenge JavaScript Tarpit")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer le challenge JavaScript Tarpit")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        javascript_tarpit_enabled = menu.run()
        if javascript_tarpit_enabled == "back" or javascript_tarpit_enabled == "exit" or javascript_tarpit_enabled == "help":
            return "back"
        
        if javascript_tarpit_enabled == "true":
            javascript_tarpit_complexity_min = IntPrompt.ask("Complexité minimale tarpit (1-10)", default=4)
            javascript_tarpit_complexity_max = IntPrompt.ask("Complexité maximale tarpit (1-10)", default=7)
            min_time_str = Prompt.ask("Temps de résolution minimum (ms)", default="100.0")
            try:
                javascript_tarpit_min_solve_time_ms = float(min_time_str)
            except ValueError:
                javascript_tarpit_min_solve_time_ms = 100.0
            max_time_str = Prompt.ask("Temps de résolution maximum (ms)", default="30000.0")
            try:
                javascript_tarpit_max_solve_time_ms = float(max_time_str)
            except ValueError:
                javascript_tarpit_max_solve_time_ms = 30000.0
        
        print_gradient_title("Challenge Cookie Cryptographique")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer le challenge cookie cryptographique")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        encrypted_cookie_challenge_enabled = menu.run()
        if encrypted_cookie_challenge_enabled == "back" or encrypted_cookie_challenge_enabled == "exit" or encrypted_cookie_challenge_enabled == "help":
            return "back"
        
        if encrypted_cookie_challenge_enabled == "true":
            encrypted_cookie_ttl = IntPrompt.ask("Durée de vie du cookie (secondes)", default=3600)
    
    def step_config_rapide():
        console.print("\n[bold yellow]⚡ Configuration Rapide Disponible[/bold yellow]")
        console.print("[dim]Vous pouvez passer toutes les étapes suivantes et utiliser les valeurs par défaut[/dim]\n")
        print_gradient_title("Configuration rapide")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Passer toutes les étapes suivantes (valeurs par défaut)")
        menu.add_option("continue", "Continuer la configuration complète", lambda: "continue")
        menu.add_option("skip", "⚡ Passer toutes les étapes (valeurs par défaut)", lambda: "skip")
        menu.add_back_option()  # Seul endroit avec le bouton retour
        menu.add_help_option()
        return menu.run()
    
    config_mode = run_menu_step(step_config_rapide, "config_rapide")
    if config_mode == "back_step":
        # Retour à l'étape précédente selon si les challenges sont activés
        if challenge_system_enabled == "true" and encrypted_cookie_challenge_enabled:
            print_gradient_title("Challenge Cookie Cryptographique")
            menu = InteractiveMenu(is_main_menu=False)
            menu.set_title("Activer le challenge cookie cryptographique")
            menu.add_option("true", "Oui", lambda: "true")
            menu.add_option("false", "Non", lambda: "false")
            menu.add_help_option()
            encrypted_cookie_challenge_enabled = menu.run()
            if encrypted_cookie_challenge_enabled == "back" or encrypted_cookie_challenge_enabled == "exit" or encrypted_cookie_challenge_enabled == "help":
                return "back"
            if encrypted_cookie_challenge_enabled == "true":
                encrypted_cookie_ttl = IntPrompt.ask("Durée de vie du cookie (secondes)", default=3600)
        else:
            # Retour au menu du système de challenge
            print_gradient_title("Système de Challenge")
            menu = InteractiveMenu(is_main_menu=False)
            menu.set_title("Activer le système de challenge")
            menu.add_option("true", "Oui", lambda: "true")
            menu.add_option("false", "Non", lambda: "false")
            menu.add_help_option()
            challenge_system_enabled = menu.run()
            if challenge_system_enabled == "back" or challenge_system_enabled == "exit" or challenge_system_enabled == "help":
                return "back"
        config_mode = run_menu_step(step_config_rapide, "config_rapide")
        if config_mode == "back_step" or config_mode == "back" or config_mode == "exit" or config_mode == "help":
            return "back"
    if config_mode == "back" or config_mode == "exit" or config_mode == "help":
        return "back"
    
    use_defaults = config_mode == "skip"
    
    if use_defaults:
        # Toutes les valeurs par défaut pour skip
        tls_fingerprinting_enabled = "true"
        staged_ddos_mitigation_enabled = "true"
        syn_cookie_enabled = "true"
        syn_cookie_max_requests_per_ip = 10
        connection_state_protection_enabled = "true"
        max_half_open_connections = 1000
        max_total_connections = 5000
        connection_threshold_warning = 0.7
        connection_threshold_critical = 0.9
        geo_filtering_enabled = "false"
        geo_attack_threshold = 100
        geo_analysis_window_minutes = 5
        connection_metrics_enabled = "true"
        connection_metrics_window_minutes = 5
        low_and_slow_threshold_bytes_per_sec = 10.0
        low_and_slow_min_duration_seconds = 60
        behavioral_malice_scoring_enabled = "true"
        malice_score_error_rate_weight = 0.25
        malice_score_low_and_slow_weight = 0.20
        malice_score_regular_timing_weight = 0.20
        malice_score_reputation_weight = 0.20
        malice_score_tls_weight = 0.15
        malice_score_critical_threshold = 0.8
        malice_score_high_threshold = 0.6
        malice_score_medium_threshold = 0.4
        # Paramètres de performance et environnement (skip tout)
        max_latency_ms = 50
        max_memory_mb = 512
        environment = "production"
        log_level = "INFO"
        # Passe directement à la génération du .env (sauter le reste)
    else:
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
        
        print_gradient_title("Protection SYN Cookie")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer la protection SYN Cookie")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        syn_cookie_enabled = menu.run()
        if syn_cookie_enabled == "back" or syn_cookie_enabled == "exit" or syn_cookie_enabled == "help":
            return "back"
        
        syn_cookie_max_requests_per_ip = 10
        if syn_cookie_enabled == "true":
            syn_cookie_max_requests_per_ip = IntPrompt.ask("Nombre max de requêtes SYN par IP", default=10)
        
        print_gradient_title("Protection Table d'État de Connexion")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer la protection de la table d'état")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        connection_state_protection_enabled = menu.run()
        if connection_state_protection_enabled == "back" or connection_state_protection_enabled == "exit" or connection_state_protection_enabled == "help":
            return "back"
        
        max_half_open_connections = 1000
        max_total_connections = 5000
        connection_threshold_warning = 0.7
        connection_threshold_critical = 0.9
        if connection_state_protection_enabled == "true":
            max_half_open_connections = IntPrompt.ask("Connexions semi-ouvertes max", default=1000)
            max_total_connections = IntPrompt.ask("Connexions totales max", default=5000)
            warning_str = Prompt.ask("Seuil d'avertissement (0.0-1.0)", default="0.7")
            try:
                connection_threshold_warning = float(warning_str)
            except ValueError:
                connection_threshold_warning = 0.7
            critical_str = Prompt.ask("Seuil critique (0.0-1.0)", default="0.9")
            try:
                connection_threshold_critical = float(critical_str)
            except ValueError:
                connection_threshold_critical = 0.9
        
        print_gradient_title("Filtrage Géographique")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer le filtrage géographique")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        geo_filtering_enabled = menu.run()
        if geo_filtering_enabled == "back" or geo_filtering_enabled == "exit" or geo_filtering_enabled == "help":
            return "back"
        
        geo_attack_threshold = 100
        geo_analysis_window_minutes = 5
        if geo_filtering_enabled == "true":
            geo_attack_threshold = IntPrompt.ask("Seuil d'attaque par région", default=100)
            geo_analysis_window_minutes = IntPrompt.ask("Fenêtre d'analyse (minutes)", default=5)
        
        connection_metrics_enabled = "true"
        connection_metrics_window_minutes = 5
        low_and_slow_threshold_bytes_per_sec = 10.0
        low_and_slow_min_duration_seconds = 60
        
        print_gradient_title("Analyse des Métriques par Connexion")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer l'analyse des métriques par connexion")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        connection_metrics_enabled = menu.run()
        if connection_metrics_enabled == "back" or connection_metrics_enabled == "exit" or connection_metrics_enabled == "help":
            return "back"
        
        if connection_metrics_enabled == "true":
            connection_metrics_window_minutes = IntPrompt.ask("Fenêtre d'analyse des métriques (minutes)", default=5)
            low_and_slow_threshold_str = Prompt.ask("Seuil Low-and-Slow (bytes/seconde)", default="10.0")
            try:
                low_and_slow_threshold_bytes_per_sec = float(low_and_slow_threshold_str)
            except ValueError:
                low_and_slow_threshold_bytes_per_sec = 10.0
            low_and_slow_min_duration_seconds = IntPrompt.ask("Durée minimale Low-and-Slow (secondes)", default=60)
        
        behavioral_malice_scoring_enabled = "true"
        malice_score_error_rate_weight = 0.25
        malice_score_low_and_slow_weight = 0.20
        malice_score_regular_timing_weight = 0.20
        malice_score_reputation_weight = 0.20
        malice_score_tls_weight = 0.15
        malice_score_critical_threshold = 0.8
        malice_score_high_threshold = 0.6
        malice_score_medium_threshold = 0.4
        
        print_gradient_title("Score de Malice Comportemental")
        menu = InteractiveMenu(is_main_menu=False)
        menu.set_title("Activer le score de malice comportemental")
        menu.add_option("true", "Oui", lambda: "true")
        menu.add_option("false", "Non", lambda: "false")
        menu.add_help_option()
        behavioral_malice_scoring_enabled = menu.run()
        if behavioral_malice_scoring_enabled == "back" or behavioral_malice_scoring_enabled == "exit" or behavioral_malice_scoring_enabled == "help":
            return "back"
        
        if behavioral_malice_scoring_enabled == "true":
            error_rate_str = Prompt.ask("Poids taux d'erreur (0.0-1.0)", default="0.25")
            try:
                malice_score_error_rate_weight = float(error_rate_str)
            except ValueError:
                malice_score_error_rate_weight = 0.25
            low_and_slow_str = Prompt.ask("Poids Low-and-Slow (0.0-1.0)", default="0.20")
            try:
                malice_score_low_and_slow_weight = float(low_and_slow_str)
            except ValueError:
                malice_score_low_and_slow_weight = 0.20
            regular_timing_str = Prompt.ask("Poids régularité temporelle (0.0-1.0)", default="0.20")
            try:
                malice_score_regular_timing_weight = float(regular_timing_str)
            except ValueError:
                malice_score_regular_timing_weight = 0.20
            reputation_str = Prompt.ask("Poids réputation IP (0.0-1.0)", default="0.20")
            try:
                malice_score_reputation_weight = float(reputation_str)
            except ValueError:
                malice_score_reputation_weight = 0.20
            tls_str = Prompt.ask("Poids TLS Fingerprinting (0.0-1.0)", default="0.15")
            try:
                malice_score_tls_weight = float(tls_str)
            except ValueError:
                malice_score_tls_weight = 0.15
            critical_str = Prompt.ask("Seuil critique (0.0-1.0)", default="0.8")
            try:
                malice_score_critical_threshold = float(critical_str)
            except ValueError:
                malice_score_critical_threshold = 0.8
            high_str = Prompt.ask("Seuil élevé (0.0-1.0)", default="0.6")
            try:
                malice_score_high_threshold = float(high_str)
            except ValueError:
                malice_score_high_threshold = 0.6
            medium_str = Prompt.ask("Seuil moyen (0.0-1.0)", default="0.4")
            try:
                malice_score_medium_threshold = float(medium_str)
            except ValueError:
                malice_score_medium_threshold = 0.4
        
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

HEADLESS_DETECTION_ENABLED={headless_detection_enabled}
HEADLESS_DETECTION_CONFIDENCE_THRESHOLD={headless_detection_confidence_threshold}

JAVASCRIPT_TARPIT_ENABLED={javascript_tarpit_enabled}
JAVASCRIPT_TARPIT_COMPLEXITY_MIN={javascript_tarpit_complexity_min}
JAVASCRIPT_TARPIT_COMPLEXITY_MAX={javascript_tarpit_complexity_max}
JAVASCRIPT_TARPIT_MIN_SOLVE_TIME_MS={javascript_tarpit_min_solve_time_ms}
JAVASCRIPT_TARPIT_MAX_SOLVE_TIME_MS={javascript_tarpit_max_solve_time_ms}

ENCRYPTED_COOKIE_CHALLENGE_ENABLED={encrypted_cookie_challenge_enabled}
ENCRYPTED_COOKIE_TTL={encrypted_cookie_ttl}

TLS_FINGERPRINTING_ENABLED={tls_fingerprinting_enabled}
STAGED_DDOS_MITIGATION_ENABLED={staged_ddos_mitigation_enabled}

SYN_COOKIE_ENABLED={syn_cookie_enabled}
SYN_COOKIE_MAX_REQUESTS_PER_IP={syn_cookie_max_requests_per_ip}

CONNECTION_STATE_PROTECTION_ENABLED={connection_state_protection_enabled}
MAX_HALF_OPEN_CONNECTIONS={max_half_open_connections}
MAX_TOTAL_CONNECTIONS={max_total_connections}
CONNECTION_THRESHOLD_WARNING={connection_threshold_warning}
CONNECTION_THRESHOLD_CRITICAL={connection_threshold_critical}

GEO_FILTERING_ENABLED={geo_filtering_enabled}
GEO_ATTACK_THRESHOLD={geo_attack_threshold}
GEO_ANALYSIS_WINDOW_MINUTES={geo_analysis_window_minutes}

CONNECTION_METRICS_ENABLED={connection_metrics_enabled}
CONNECTION_METRICS_WINDOW_MINUTES={connection_metrics_window_minutes}
LOW_AND_SLOW_THRESHOLD_BYTES_PER_SEC={low_and_slow_threshold_bytes_per_sec}
LOW_AND_SLOW_MIN_DURATION_SECONDS={low_and_slow_min_duration_seconds}

BEHAVIORAL_MALICE_SCORING_ENABLED={behavioral_malice_scoring_enabled}
MALICE_SCORE_ERROR_RATE_WEIGHT={malice_score_error_rate_weight}
MALICE_SCORE_LOW_AND_SLOW_WEIGHT={malice_score_low_and_slow_weight}
MALICE_SCORE_REGULAR_TIMING_WEIGHT={malice_score_regular_timing_weight}
MALICE_SCORE_REPUTATION_WEIGHT={malice_score_reputation_weight}
MALICE_SCORE_TLS_WEIGHT={malice_score_tls_weight}
MALICE_SCORE_CRITICAL_THRESHOLD={malice_score_critical_threshold}
MALICE_SCORE_HIGH_THRESHOLD={malice_score_high_threshold}
MALICE_SCORE_MEDIUM_THRESHOLD={malice_score_medium_threshold}

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
        nginx_config = generate_nginx_config(rate_limit_requests, rate_limit_burst, ddos_max_connections, syn_cookie_enabled)
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
    return None

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

