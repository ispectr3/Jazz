import json
import os
import subprocess
from app.plugins.base import ScannerAdapter
from app.plugins.loader import register


@register()
class SupabombAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "Supabomb"

    def validate_input(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
            return "credentials" in data or "tables" in data or "summary" in data
        except Exception:
            return False

    def normalize(self, raw_data: str, project_id: int) -> list:
        data = json.loads(raw_data)
        findings = []
        base = {"project_id": project_id, "plugin_source": self.name}

        creds = data.get("credentials", {})
        if creds:
            findings.append({**base,
                "title": "Supabase Credentials Found",
                "description": (
                    f"Project Ref: {creds.get('project_ref', 'N/A')}\n"
                    f"URL: {creds.get('url', 'N/A')}\n"
                    f"Anon Key: {creds.get('anon_key', 'N/A')[:20]}..."
                ),
                "severity": "Alta",
                "raw_data": creds})

        enum = data.get("enumeration", {})
        tables = enum.get("tables", [])
        for t in tables:
            if t.get("accessible"):
                findings.append({**base,
                    "title": f"Supabase Table Exposed: {t['name']}",
                    "description": (
                        f"Table: {t['name']}\n"
                        f"Columns: {', '.join(t.get('columns', []))}\n"
                        f"Row Count: {t.get('row_count', 0)}\n"
                        f"Write Permissions: {t.get('write_permissions', 'N/A')}"
                    ),
                    "severity": "Média",
                    "raw_data": t})

        rpcs = enum.get("rpc_functions", [])
        for r in rpcs:
            if r.get("accessible"):
                findings.append({**base,
                    "title": f"Supabase RPC Function Exposed: {r['name']}",
                    "description": (
                        f"Function: {r['name']}\n"
                        f"Parameters: {r.get('parameters', [])}"
                    ),
                    "severity": "Média",
                    "raw_data": r})

        buckets = enum.get("storage_buckets", [])
        for b in buckets:
            if isinstance(b, dict) and b.get("public"):
                findings.append({**base,
                    "title": f"Supabase Public Storage Bucket: {b.get('name', 'unknown')}",
                    "description": f"Bucket: {b.get('name')}\nFiles: {b.get('file_count', 0)}",
                    "severity": "Média",
                    "raw_data": b})

        dump = data.get("dump", {})
        tables_dumped = dump.get("tables", {})
        for tname, tdata in tables_dumped.items():
            rows = tdata.get("data", [])
            if rows:
                findings.append({**base,
                    "title": f"Supabase Data Dump: {tname}",
                    "description": (
                        f"Table: {tname}\n"
                        f"Rows: {tdata.get('row_count', 0)}\n"
                        f"Sample: {json.dumps(rows[:2], indent=2)[:200]}"
                    ),
                    "severity": "Crítica",
                    "raw_data": {"table": tname, "data": rows}})

        summary = data.get("summary", {})
        if summary:
            findings.append({**base,
                "title": "Supabomb Scan Summary",
                "description": (
                    f"Tables Discovered: {summary.get('tables_discovered', 0)}\n"
                    f"RPC Functions: {summary.get('rpc_functions_discovered', 0)}\n"
                    f"Buckets: {summary.get('storage_buckets_discovered', 0)}\n"
                    f"Tables Dumped: {summary.get('tables_dumped', 0)}"
                ),
                "severity": "Info",
                "raw_data": summary})

        return findings

    def run_discover(self, target_url: str) -> str:
        tool_dir = os.path.join(os.getcwd(), '.tools', 'supabomb')
        cmd = ["supabomb", "discover", "--url", target_url, "--json"]
        result = subprocess.run(cmd, cwd=tool_dir, capture_output=True, text=True, check=False)
        return result.stdout

    def run_full_scan(self, target_url: str, output_file: str) -> str:
        tool_dir = os.path.join(os.getcwd(), '.tools', 'supabomb')
        cmd = [
            "supabomb", "all", "--url", target_url,
            "--output", output_file, "--test-write", "--json"
        ]
        result = subprocess.run(cmd, cwd=tool_dir, capture_output=True, text=True, check=False)
        return result.stdout
