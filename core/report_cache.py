from copy import deepcopy
from time import time
from typing import Optional
from core.configuration import env_configuration


class ReportCache:
    def __init__(self, ttl: int):
        self._ttl = ttl
        self._cache = {}

    def store(self, query: str, report: dict):
        self._cache[query] = time()+self._ttl, deepcopy(report)

    def get(self, query: str) -> Optional[dict]:
        if query not in self._cache:
            return

        expiry, report = self._cache[query]
        if expiry > time():
            return deepcopy(report)
        del self._cache[query]


cache = ReportCache(env_configuration.report_cache_ttl)
