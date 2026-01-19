from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class DriverSightReporter:
    def __init__(self, findings):
        self.findings = sorted(findings, key=lambda x: x["priority"], reverse=True)
        self.dt_now = datetime.now()
        self.timestamp = self.dt_now.strftime("%Y-%m-%d %H:%M:%S")
        self.filename = self.dt_now.strftime("DS_Report_%Y%m%d_%H%M%S.html")

    def report_to_console(self, duration=0, total_scanned=0):
        """Вывод краткой сводки в консоль."""
        avg_time = (duration / total_scanned * 1000) if total_scanned > 0 else 0

        metrics_text = (
            f"Общее время анализа: [bold white]{duration:.2f} сек.[/bold white]\n"
            f"Среднее время на модуль: [bold white]{avg_time:.2f} мс[/bold white]\n"
            f"Всего проверено модулей: [bold white]{total_scanned}[/bold white]"
        )
        console.print(
            Panel(
                metrics_text,
                title="[bold cyan]Метрики[/bold cyan]",
                border_style="bright_blue",
                expand=False,
            )
        )

        if not self.findings:
            console.print(
                Panel(
                    "[bold green]✅ Уязвимых модулей не обнаружено.[/bold green]",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"Обнаруженные риски - {self.timestamp}", header_style="bold cyan"
        )
        table.add_column("Уровень", justify="center")
        table.add_column("Имя драйвера")
        table.add_column("Рекомендация", style="yellow")

        for f in self.findings:
            risk_color = "red" if f["priority"] >= 9 else "yellow"
            remediation = (
                "Блокировка / Удаление" if f["priority"] >= 8 else "Обновление ПО"
            )
            table.add_row(
                f"[{risk_color}]{f['priority']}/10[/{risk_color}]",
                f["name"],
                remediation,
            )

        console.print(table)

    def _get_css(self, is_clean):
        main_color = "#2ea043" if is_clean else "#38d3ff"
        return f"""
        body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 20px; line-height: 1.5; }}
        .container {{ max-width: 1000px; margin: auto; }}
        .header {{ border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-bottom: 20px; }}
        h1 {{ color: {main_color}; font-size: 22px; margin-bottom: 5px; }}
        .summary-box {{ padding: 15px; border-radius: 6px; background: #161b22; border: 1px solid #30363d; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ background: #21262d; color: {main_color}; text-align: left; padding: 10px; border: 1px solid #30363d; font-size: 13px; }}
        td {{ padding: 10px; border: 1px solid #30363d; vertical-align: top; font-size: 14px; }}
        .risk-high {{ color: #ff3e3e; font-weight: bold; }}
        .path {{ font-size: 12px; color: #8b949e; font-family: monospace; word-break: break-all; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #484f58; text-align: center; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        """

    def report_to_html(self):
        """Генерация расширенного технического вывода в HTML."""
        is_clean = len(self.findings) == 0
        rows_html = ""

        status_text = (
            "УГРОЗ НЕ ОБНАРУЖЕНО"
            if is_clean
            else f"ОБНАРУЖЕНО РИСКОВ: {len(self.findings)}"
        )
        status_color = "#2ea043" if is_clean else "#ff3e3e"

        for f in self.findings:
            risk_class = "risk-high" if f["priority"] >= 9 else ""
            rows_html += f"""
            <tr>
                <td class="{risk_class}">{f["priority"]}/10</td>
                <td>
                    <strong>{f["name"]}</strong><br>
                    <div class="path">{f["path"]}</div>
                    <code style="font-size:11px">SHA256: {f["hash"]}</code>
                </td>
                <td>
                    {f["vuln_type"]}<br>
                    <a href="{f["exploit_url"]}" target="_blank">→ Технические подробности</a>
                </td>
            </tr>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>DriverSight Result</title>
            <style>{self._get_css(is_clean)}</style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>DriverSight: Результаты сканирования</h1>
                    <span style="color:#8b949e">Дата анализа: {self.timestamp}</span>
                </div>
                
                <div class="summary-box">
                    <b style="color:{status_color}">{status_text}</b><br>
                    <small style="color:#8b949e">Анализ проведен на основе сигнатур проекта LOLDrivers.</small>
                </div>

                {"<table><thead><tr><th>Риск</th><th>Модуль и путь</th><th>Тип угрозы</th></tr></thead><tbody>" + rows_html + "</tbody></table>" if not is_clean else ""}

                <div class="footer">
                    Сгенерировано инструментом DriverSight v1.2<br>
                    Использование WinAPI EnumDeviceDrivers для инвентаризации объектов ядра.
                </div>
            </div>
        </body>
        </html>
        """

        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(html_content)

        return self.filename
