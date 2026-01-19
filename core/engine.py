import json
import time
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.collector import DriverCollector
from core.hasher import DriverHasher
from core.analyzer import DriverAnalyzer
from utils.interface import print_info


class DriverSightEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.collector = DriverCollector()
        self.hasher = DriverHasher()

    def run_scan(self):
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                database = json.load(f)
            analyzer = DriverAnalyzer(database)
        except Exception as e:
            raise Exception(f"Failed to load database: {e}")

        found_threats = []
        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(
                description="Enumerating kernel modules (WinAPI)...", total=None
            )
            paths = self.collector.get_driver_paths()
            total_drivers = len(paths)
            print_info(
                f"Identified [bold white]{total_drivers}[/bold white] active drivers."
            )

            task = progress.add_task(
                description="Analyzing drivers...", total=total_drivers
            )
            for path in paths:
                f_hash = self.hasher.get_sha256(path)
                if f_hash:
                    res = analyzer.evaluate(path, f_hash)
                    if res:
                        found_threats.append(res)
                progress.advance(task)

        duration = time.time() - start_time
        return found_threats, duration, total_drivers
