"""PyInstaller build script for OSINT FOX."""
import os
import sys
import subprocess

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "dist")
ICON_PATH = os.path.join(os.path.dirname(__file__), "assets", "fox.ico")

HIDDEN_IMPORTS = [
    "app",
    "app.gui",
    "app.theme",
    "app.settings",
    "app.session",
    "modules",
    "modules.base",
    "modules.registry",
    "modules.username",
    "modules.email",
    "modules.phone",
    "modules.domain",
    "modules.social",
    "modules.image",
    "modules.breaches",
    "modules.geo",
    "utils",
    "utils.exporter",
    "utils.network",
    "utils.apikeys",
    "utils.cache",
    "customtkinter",
    "PIL",
    "PIL._imaging",
    "PIL._webp",
    "requests",
    "fpdf",
    "dns",
    "dns.resolver",
    "phonenumbers",
    "whois",
    "pytz",
]

def build_exe():
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath", OUTPUT_DIR,
        "--name", "OSINT_FOX",
    ]
    for mod in HIDDEN_IMPORTS:
        args.extend(["--hidden-import", mod])

    try:
        subprocess.run(args + [
            "--onedir",
            "--windowed",
            os.path.join(os.path.dirname(__file__), "main.py"),
        ], check=True)
        print("[+] GUI build complete")
    except subprocess.CalledProcessError as e:
        print(f"[-] GUI build failed: {e}")
        sys.exit(1)

def build_cli():
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath", OUTPUT_DIR,
        "--name", "OSINT_FOX_CLI",
    ]
    for mod in HIDDEN_IMPORTS:
        args.extend(["--hidden-import", mod])

    try:
        subprocess.run(args + [
            "--onedir",
            "--console",
            os.path.join(os.path.dirname(__file__), "main.py"),
        ], check=True)
        print("[+] CLI build complete")
    except subprocess.CalledProcessError as e:
        print(f"[-] CLI build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if "--cli" in sys.argv:
        build_cli()
    elif "--gui" in sys.argv:
        build_exe()
    else:
        build_exe()
        build_cli()
