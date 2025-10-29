def part_ColorLine(current_line: str = "-----------------------", color: str = "cyan"):
    """Affiche une ligne en couleur dans le terminal"""
    
    # Codes ANSI pour les couleurs de texte
    colors = {
        "black": "\033[30m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",
        "reset": "\033[0m"
    }

    color_code = colors.get(color.lower(), colors["cyan"])
    reset_code = colors["reset"]

    print(f"{color_code}{current_line}{reset_code}")