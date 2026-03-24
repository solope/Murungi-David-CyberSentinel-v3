"""Shared chain-of-custody logger used by all modules."""
import datetime


class CustodyLog:
    def __init__(self):
        self.entries = []

    def log(self, action: str, target: str = "", details: str = "",
            analyst: str = "EXAMINER_01"):
        self.entries.append({
            "id":       len(self.entries) + 1,
            "ts":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analyst":  analyst,
            "action":   action,
            "target":   target,
            "details":  details,
        })
