from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import sys
import os
import time
import math

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

class InteractiveMenu:
    def __init__(self, is_main_menu: bool = False):
        self.options = []
        self.current_index = 0
        self.title = ""
        self.running = True
        self.is_main_menu = is_main_menu
    
    def add_option(self, key: str, label: str, callback):
        self.options.append({
            "key": key,
            "label": label,
            "callback": callback
        })
    
    def set_title(self, title: str):
        self.title = title
    
    def add_help_option(self):
        if not self.is_main_menu:
            self.add_option("help", "Aide (Retour au menu principal)", lambda: "back")
    
    def add_back_option(self):
        """Ajoute uniquement l'option retour (à utiliser seulement à un endroit spécifique)"""
        if not self.is_main_menu:
            self.add_option("back", "← Retour", lambda: "back_step")
    
    def display(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print()
        
        banner = gradient_text("PyWaf Client")
        console.print(banner)
        console.print()
        
        if self.title:
            title_gradient = gradient_text(self.title)
            console.print(title_gradient)
            console.print()
        
        menu_text = Text()
        for i, option in enumerate(self.options):
            if i > 0:
                menu_text.append("\n")
            
            if i == self.current_index:
                option_gradient = gradient_text(f"> {option['label']}")
                menu_text.append(option_gradient)
            else:
                menu_text.append(f"  {option['label']}", style="dim")
        
        console.print(Panel(menu_text, border_style="#FFD700", padding=(1, 2)))
        console.print()
        help_text = gradient_text("Utilisez les flèches ↑↓ pour naviguer, Entrée pour sélectionner, Q pour quitter")
        dim_help = Text()
        full_help_text = help_text.plain
        help_spans = sorted(help_text._spans, key=lambda s: s.start)
        
        last_pos = 0
        for span in help_spans:
            if span.start > last_pos:
                dim_help.append(full_help_text[last_pos:span.start], style="dim")
            
            text_content = full_help_text[span.start:span.end]
            if span.style:
                style_parts = span.style.split()
                color = style_parts[-1] if style_parts and style_parts[-1].startswith("#") else None
                if color:
                    dim_help.append(text_content, style=f"dim {color}")
                else:
                    dim_help.append(text_content, style="dim")
            else:
                dim_help.append(text_content, style="dim")
            
            last_pos = span.end
        
        if last_pos < len(full_help_text):
            dim_help.append(full_help_text[last_pos:], style="dim")
        
        console.print(dim_help)
    
    def run(self):
        import msvcrt
        
        while self.running:
            self.display()
            
            try:
                if sys.platform == "win32":
                    key = msvcrt.getch()
                    
                    if key == b'\xe0':
                        key = msvcrt.getch()
                        if key == b'H':
                            self.current_index = max(0, self.current_index - 1)
                        elif key == b'P':
                            self.current_index = min(len(self.options) - 1, self.current_index + 1)
                    elif key == b'\r':
                        selected = self.options[self.current_index]
                        console.print()
                        result = selected["callback"]()
                        if result == "back":
                            return "back"
                        elif result == "exit":
                            return "exit"
                        self.running = False
                        return result
                    elif key in [b'q', b'Q', b'\x1b']:
                        if self.is_main_menu:
                            return "exit"
                        else:
                            return "back"
                else:
                    import select
                    import tty
                    import termios
                    
                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    try:
                        tty.setraw(sys.stdin.fileno())
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            key = sys.stdin.read(1)
                            
                            if key == '\x1b':
                                key = sys.stdin.read(2)
                                if key == '[A':
                                    self.current_index = max(0, self.current_index - 1)
                                elif key == '[B':
                                    self.current_index = min(len(self.options) - 1, self.current_index + 1)
                            elif key == '\r':
                                selected = self.options[self.current_index]
                                console.print()
                                result = selected["callback"]()
                                if result == "back":
                                    return "back"
                                elif result == "exit":
                                    return "exit"
                                self.running = False
                                return result
                            elif key in ['q', 'Q']:
                                if self.is_main_menu:
                                    return "exit"
                                else:
                                    return "back"
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                
                time.sleep(0.05)
            except KeyboardInterrupt:
                return "exit"
            except Exception as e:
                console.print(f"[bold red]Erreur: {str(e)}[/bold red]")
                time.sleep(1)
        
        return None

