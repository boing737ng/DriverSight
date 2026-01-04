class DriverAnalyzer:
    def __init__(self, database):
        self.db = database

    def evaluate(self, driver_path, file_hash):
        match = self.db.get(file_hash)
        if not match:
            return None

        raw_severity = match.get("severity", 5)
        vuln_type = match.get("type", "Unknown Vulnerability").lower()

        priority = raw_severity
        if "write" in vuln_type:
            priority = 10
        elif "read" in vuln_type:
            priority = 8
        elif "leak" in vuln_type:
            priority = 6

        return {
            "path": driver_path,
            "hash": file_hash,
            "name": match.get("name", "Unknown Driver"),
            "vuln_type": match.get("type", "Vulnerable Driver"),
            "priority": priority,
            "exploit_url": match.get("exploit", "https://loldrivers.io/"),
            "action": "Critical: Immediate removal required"
            if priority >= 9
            else "High: Monitor/Disable",
        }
