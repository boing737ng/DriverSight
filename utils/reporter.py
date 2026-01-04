from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class DriverSightReporter:
    def __init__(self, findings):
        self.findings = sorted(findings, key=lambda x: x["priority"], reverse=True)
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def report_to_console(self):
        if not self.findings:
            console.print(
                Panel(
                    "[bold green]✅ SYSTEM CLEAN:[/bold green] No vulnerable drivers found.",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"DriverSight Scan Report - {self.timestamp}",
            header_style="bold magenta",
        )
        table.add_column("Score", justify="center")
        table.add_column("Driver Name", style="cyan")
        table.add_column("Vulnerability Type", style="white")
        table.add_column("Action", style="yellow")

        for f in self.findings:
            color = "red" if f["priority"] >= 8 else "yellow"
            table.add_row(
                f"[{color}]{f['priority']}/10[/{color}]",
                f["name"],
                f["vuln_type"],
                f["action"],
            )
        console.print(table)

    def _get_css(self, is_clean):
        main_color = "#2ea043" if is_clean else "#ff3e3e"
        return f"""
        body {{ background: #0d1117; color: #c9d1d9; font-family: sans-serif; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; }}
        .header {{ border-bottom: 2px solid {main_color}; padding-bottom: 10px; margin-bottom: 20px; }}
        h1 {{ color: {main_color}; margin: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #161b22; }}
        th, td {{ padding: 12px; text-align: left; border: 1px solid #30363d; }}
        th {{ background: #21262d; color: {main_color}; }}
        .high {{ color: #ff3e3e; font-weight: bold; }}
        .path {{ font-size: 0.85em; color: #8b949e; font-family: monospace; }}
        .status-box {{ padding: 15px; border-radius: 5px; background: #21262d; border: 1px solid #30363d; }}
        """

    def report_to_html(self, filename="DS_Report.html"):
        is_clean = len(self.findings) == 0
        rows = ""

        if is_clean:
            status_html = "<div class='status-box'><b style='color:#2ea043'>✅ СИСТЕМА БЕЗОПАСНА:</b> Уязвимых драйверов в памяти не обнаружено.</div>"
        else:
            status_html = f"<div class='status-box'><b style='color:#ff3e3e'>⚠ ОБНАРУЖЕНО УГРОЗ: {len(self.findings)}</b></div>"
            for f in self.findings:
                p_class = "high" if f["priority"] >= 8 else ""
                rows += f"""
                <tr>
                    <td class="{p_class}">{f["priority"]}/10</td>
                    <td><strong>{f["name"]}</strong><br><span class="path">{f["path"]}</span></td>
                    <td><em>{f["vuln_type"]}</em><br><a href="{f["exploit_url"]}" style="color:#58a6ff">Эксплойт / Подробности</a></td>
                </tr>"""

        html = f"""
        <!DOCTYPE html>
        <html><head><meta charset="UTF-8"><style>{self._get_css(is_clean)}</style></head>
        <body><div class="container">
            <div class="header"><h1>DriverSight Audit Report</h1><small>{self.timestamp}</small></div>
            {status_html}
            {"<table><thead><tr><th>Score</th><th>Driver Info</th><th>Vulnerability</th></tr></thead><tbody>" + rows + "</tbody></table>" if not is_clean else ""}
            <p style='margin-top:30px; font-size:0.8em; color:#484f58'>Сгенерировано DriverSight v1.2 | Соответствует ФЗ-187</p>
        </div></body></html>
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
