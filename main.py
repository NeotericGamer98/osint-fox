import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def cli_mode():
    import argparse
    from modules.registry import discover_modules, get_module
    from utils.exporter import EXPORT_FORMATS

    parser = argparse.ArgumentParser(
        description="OSINT FOX v1.2 - Open Source Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --cli --module username --target johndoe
  python main.py --cli --module email --target user@example.com --format json --output report.json
  python main.py --cli --module domain --target example.com --proxy socks5://127.0.0.1:9050
        """
    )
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument("-m", "--module", default="username",
                        choices=["username", "email", "phone", "domain",
                                 "social", "image", "breaches", "geo"],
                        help="Module to use")
    parser.add_argument("-t", "--target", required=True, help="Target to scan")
    parser.add_argument("-f", "--format", default="txt",
                        choices=["txt", "json", "csv", "html"],
                        help="Output format")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--proxy", help="Proxy URL (e.g. socks5://127.0.0.1:9050)")

    args = parser.parse_args()

    if args.proxy:
        from utils.network import set_proxy
        set_proxy(args.proxy)
        print(f"[*] Using proxy: {args.proxy}")

    module_map = {
        "username": "Username OSINT",
        "email": "Email OSINT",
        "phone": "Phone OSINT",
        "domain": "Domain OSINT",
        "social": "Social Analyzer",
        "image": "Image OSINT",
        "breaches": "Breach Lookup",
        "geo": "Geolocation",
    }

    module_name = module_map.get(args.module, "Username OSINT")
    discover_modules()
    module = get_module(module_name)
    if not module:
        print(f"[-] Module '{module_name}' not found")
        sys.exit(1)

    def progress(msg, pct):
        print(f"  [{int(pct*100)}%] {msg}", file=sys.stderr)

    print(f"[*] Starting {module_name} scan on '{args.target}'...")
    results = module.scan(args.target, progress)
    flat = module.get_results_flat()
    print(f"[+] Scan complete!")

    if args.output:
        if args.format == "txt":
            export_to_txt(flat, args.output, args.target)
        elif args.format == "json":
            export_to_json(flat, args.output, args.target)
        elif args.format == "csv":
            export_to_csv(flat, args.output, args.target)
        elif args.format == "html":
            export_to_html(flat, args.output, args.target)
        print(f"[+] Report saved to: {args.output}")
    else:
        for key, val in flat:
            if key and val:
                print(f"{key}: {val}")
            elif not key and not val:
                print()


def gui_mode():
    from app.gui import OSINTFoxApp
    app = OSINTFoxApp()
    app.run()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        cli_mode()
    else:
        gui_mode()
