from datetime import datetime
from queue import Queue
from time import sleep
from typing import Iterable, List, Optional
from core.github.parsers import package_processors
from core.github.repository import Repository
from core.graph_database.contracts import Dependency
from core.configuration import env_configuration
from core.report_cache import cache


class CountedQueue:
    def __init__(self):
        self.queue = Queue()
        self.processed = self.total = 0

    def put(self, item):
        self.queue.put(item)
        self.total += 1

    def get(self):
        self.processed += 1
        return self.queue.get()

    def empty(self) -> bool:
        return self.total == self.processed


class GraphBuilder:
    def __init__(self, url: str):
        self._graphdb_client = env_configuration.graphdb_factory()
        self._url = url

        self._processing_queue = CountedQueue()
        self._dependencies = []
        self._seen = set()
        self._dependency_graph = []
        self._vulnerability_graph = []

    def get_cached_report(self) -> Optional[dict]:
        return cache.get(self._url)

    def stream_process_repository(self) -> Iterable[str]:
        yield {"status": "Queued for processing."}
        sleep(0.1)  # todo: implement a queue for spikes in traffic?

        self._processing_queue.put(Repository.from_url(self._url))

        while not self._processing_queue.empty():
            item = self._processing_queue.get()
            if isinstance(item, Repository):
                if item in self._seen:
                    continue

                for status in self._process_repository(item):
                    processed, total = self._processing_queue.processed, self._processing_queue.total
                    yield {"status": f"Processing ({processed}/{total})... {status}"}

            elif isinstance(item, Dependency):
                for status in package_processors[item.type](self, item.name, item.version):
                    processed, total = self._processing_queue.processed, self._processing_queue.total
                    yield {"status": f"Processing ({processed}/{total})... {status}"}

        yield {"status": f"Generating report..."}
        self._store_report()

    def _store_report(self):
        edges = []

        packages = {self._url.split("/")[-1]: "repository"}

        for package_name, package_type, dependency in self._dependency_graph:
            packages[dependency.name] = package_type

            edges.append({
                "from": package_name, "to": dependency.name,
                "type": "dependency", "version": dependency.version.key
            })

        aggregated_vulnerabilities = {}
        for package_name, vulnerabilities in self._vulnerability_graph:
            for vulnerability in vulnerabilities:
                if vulnerability.cve not in aggregated_vulnerabilities:
                    aggregated_vulnerabilities[vulnerability.cve] = self._graphdb_client.get_cve_info(vulnerability.cve)
                edges.append({
                    "from": package_name, "to": vulnerability.cve,
                    "type": "vulnerability", "affected_version": vulnerability.version.key
                })

        vertices = [{
            "name": name, "type": "package", "package_type": package_type
        } for name, package_type in packages.items()]
        # noinspection PyTypeChecker
        vertices.extend([{
            "name": cve_name, "type": "CVE", "description": cve.description,
            "cvss_v2_score": cve.cvss_v2_score, "cvss_v3_score": cve.cvss_v3_score,
            "publish_date": cve.publish_date.strftime("%Y-%m-%d") if cve.publish_date else None
        } for cve_name, cve in aggregated_vulnerabilities.items()])

        cache.store(self._url, {"vertices": vertices, "edges": edges, "meta": {
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }})

    def _process_repository(self, repo: Repository) -> Iterable[str]:
        if repo.can_clone:  # otherwise, it's already a folder on disk
            yield f"Cloning {repo.name}..."
            repo.clone()

        try:
            yield f"Scanning {repo.name} for vulnerabilities..."
            vulnerabilities = self._graphdb_client.get_package_vulnerabilities(repo.name, repo.version)
            self._vulnerability_graph.append((repo.name, list(vulnerabilities)))

            yield f"Parsing {repo.name} dependencies..."
            new_dependencies = list(repo.parse_direct_dependencies())
            self._graphdb_client.insert_dependencies_for_package(repo.name, repo.version, new_dependencies)
            self.include_dependencies(repo.name, "repository", new_dependencies)
            self._seen.add(repo.name)

        finally:
            repo.cleanup()

    def include_dependencies(self, root: str, package_type: str, new_dependencies: List[Dependency]) -> None:
        for dependency in new_dependencies:
            self._dependency_graph.append((root, package_type, dependency))
            if dependency.name not in self._seen:
                self._processing_queue.put(dependency)
                self._seen.add(dependency.name)

    def include_repo(self, repo: Repository):
        self._processing_queue.put(repo)
