from datetime import datetime


class OSINTModule:
    def __init__(self, name, icon, description):
        self.name = name
        self.icon = icon
        self.description = description
        self.results = {}
        self.status = "idle"

    def scan(self, target):
        self.results = {}
        self.status = "scanning"

    def get_results(self):
        return self.results

    def get_summary(self):
        total = sum(len(v) for v in self.results.values())
        found = sum(1 for v in self.results.values() if any(
            isinstance(i, dict) and i.get("found") for i in (v if isinstance(v, list) else [v])
        ))
        return {"total": total, "found": found}

    def get_results_flat(self):
        flat = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        flat.append(("Scan Time", now))
        flat.append(("Module", self.name))
        flat.append(("Description", self.description))
        flat.append(("", ""))
        for category, items in self.results.items():
            flat.append((f"[{category}]", ""))
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            flat.append((f"  {k}", str(v) if v else "N/A"))
                    else:
                        flat.append(("  Item", str(item)))
            elif isinstance(items, dict):
                for k, v in items.items():
                    flat.append((f"  {k}", str(v) if v else "N/A"))
            else:
                flat.append(("  Data", str(items)))
            flat.append(("", ""))
        return flat
