from datetime import datetime


class OSINTModule:
    def __init__(self, name, icon, description):
        self.name = name
        self.icon = icon
        self.description = description
        self.results = {}
        self.status = "idle"

    def scan(self, target, progress_callback=None):
        self.results = {}
        self.status = "scanning"

    def get_results(self):
        return self.results

    def get_summary(self):
        total = sum(len(v) if isinstance(v, (list, dict)) else 1 for v in self.results.values())
        found = 0
        for v in self.results.values():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and item.get("found"):
                        found += 1
            elif isinstance(v, dict):
                for k2, v2 in v.items():
                    if isinstance(v2, str) and "found" in v2.lower():
                        found += 1
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


class ModuleMeta:
    def __init__(self, name, icon, description, module_class, inputs):
        self.name = name
        self.icon = icon
        self.description = description
        self.module_class = module_class
        self.inputs = inputs
