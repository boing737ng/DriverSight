from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class DriverSightReporter:
    def __init__(self, findings):
        # Сортируем: самые критичные для исправления — вверх
        self.findings = sorted(findings, key=lambda x: x["priority"], reverse=True)
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def report_to_console(self, duration=0, total_scanned=0):
        """Вывод результатов аудита в консоль с метриками времени."""

        # Расчет среднего времени (в миллисекундах, так как на один драйвер уходит очень мало)
        avg_time = (duration / total_scanned * 1000) if total_scanned > 0 else 0

        # Вывод метрик производительности
        metrics_text = (
            f"Общее время сканирования: [bold white]{duration:.2f} сек.[/bold white]\n"
            f"Среднее время на модуль: [bold white]{avg_time:.2f} мс[/bold white]\n"
            f"Всего проверено модулей: [bold white]{total_scanned}[/bold white]"
        )
        console.print(
            Panel(
                metrics_text,
                title="[bold cyan]Performance Metrics[/bold cyan]",
                border_style="bright_blue",
                expand=False,
            )
        )

        if not self.findings:
            console.print(
                Panel(
                    "[bold green]✅ АУДИТ ЗАВЕРШЕН: СИСТЕМА СООТВЕТСТВУЕТ ТРЕБОВАНИЯМ[/bold green]",
                    border_style="green",
                )
            )
            return

        console.print(
            f"\n[bold yellow]⚠ ВНИМАНИЕ: ОБНАРУЖЕНЫ РИСКИ БЕЗОПАСНОСТИ ЯДРА ({len(self.findings)})[/bold yellow]\n"
        )

        table = Table(
            title=f"Отчет по инвентаризации уязвимых модулей - {self.timestamp}",
            header_style="bold cyan",
            border_style="bright_blue",
        )

        table.add_column("Уровень риска", justify="center", style="bold")
        table.add_column("Имя драйвера", style="white")
        table.add_column("Тип уязвимости", style="dim")
        table.add_column("Рекомендация по защите", style="italic")

        for f in self.findings:
            # Цветовая индикация срочности исправления
            risk_color = "red" if f["priority"] >= 9 else "yellow"

            # Превращаем Red Team действия в Blue Team рекомендации
            remediation = (
                "Блокировка (WDAC/HVCI)" if f["priority"] >= 8 else "Обновление вендора"
            )

            table.add_row(
                f"[{risk_color}]{f['priority']}/10[/{risk_color}]",
                f["name"],
                f["vuln_type"],
                f"[bold white]{remediation}[/bold white]",
            )

        console.print(table)

    def _get_css(self, is_clean):
        """Профессиональный Blue Team дизайн."""
        main_color = "#2ea043" if is_clean else "#38d3ff"
        return f"""
        body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; padding: 30px; }}
        .container {{ max-width: 1000px; margin: auto; border: 1px solid #30363d; padding: 20px; border-radius: 8px; background: #161b22; }}
        .header {{ border-bottom: 2px solid {main_color}; padding-bottom: 15px; margin-bottom: 25px; }}
        h1 {{ color: {main_color}; margin: 0; font-size: 24px; }}
        .compliance-tag {{ float: right; background: #21262d; padding: 5px 10px; border-radius: 4px; border: 1px solid #30363d; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border: 1px solid #30363d; }}
        th {{ background: #21262d; color: {main_color}; text-transform: uppercase; font-size: 13px; }}
        .risk-high {{ color: #ff3e3e; font-weight: bold; }}
        .risk-med {{ color: #ffa657; }}
        .path {{ font-size: 0.85em; color: #8b949e; font-family: 'Consolas', monospace; }}
        .footer {{ margin-top: 40px; font-size: 0.8em; color: #484f58; text-align: center; border-top: 1px solid #30363d; padding-top: 10px; }}
        """

    def report_to_html(self, filename="DS_Audit_Report.html"):
        """Генерация детального отчета для ИБ-отдела."""
        is_clean = len(self.findings) == 0
        rows_html = ""

        if is_clean:
            status_box = f"""
            <div style="background: #1b2a1e; border: 1px solid #2ea043; padding: 20px; border-radius: 6px;">
                <h3 style="color: #2ea043; margin-top: 0;">✅ Система проверена</h3>
                На момент проверки ({self.timestamp}) уязвимых модулей ядра, входящих в актуальные списки угроз (LOLDrivers), не обнаружено. 
                Система соответствует базовым требованиям безопасности КИИ.
            </div>
            """
        else:
            status_box = f"""
            <div style="background: #2a1b1b; border: 1px solid #ff3e3e; padding: 20px; border-radius: 6px;">
                <h3 style="color: #ff3e3e; margin-top: 0;">⚠ Обнаружены несоответствия</h3>
                Выявлено объектов: {len(self.findings)}. Требуется проведение мероприятий по минимизации поверхности атаки.
            </div>
            """
            for f in self.findings:
                risk_class = "risk-high" if f["priority"] >= 9 else "risk-med"
                rows_html += f"""
                <tr>
                    <td class="{risk_class}">{f["priority"]}/10</td>
                    <td>
                        <strong>{f["name"]}</strong><br>
                        <span class="path">{f["path"]}</span><br>
                        <small style="color:#484f58">SHA256: {f["hash"]}</small>
                    </td>
                    <td>
                        {f["vuln_type"]}<br>
                        <a href="{f["exploit_url"]}" target="_blank" style="color: #58a6ff; font-size: 12px;">Техническое описание (CVE)</a>
                    </td>
                </tr>
                """

        # Сборка финального HTML
        html_content = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>DriverSight Audit Report</title>
            <style>{self._get_css(is_clean)}</style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <span class="compliance-tag">Compliance: ФЗ-187 / КИИ</span>
                    <h1>DriverSight: Отчет аудита безопасности ядра</h1>
                    <small>Дата проведения: {self.timestamp}</small>
                </div>
                
                {status_box}

                {"<table><thead><tr><th>Приоритет</th><th>Сведения о модуле</th><th>Анализ уязвимости</th></tr></thead><tbody>" + rows_html + "</tbody></table>" if not is_clean else ""}

                <div class="footer">
                    Документ сформирован DriverSight v1.2. Предназначен для внутреннего использования ИТ и ИБ отделами.<br>
                    Идентификация угроз проведена на основе актуальной базы LOLDrivers.
                </div>
            </div>
        </body>
        </html>
        """

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(
            f"[bold green]✔[/bold green] Детальный отчет для ИБ-отдела сохранен: [underline]{filename}[/underline]"
        )
