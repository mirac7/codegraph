from typing import Iterable, List
from core.graph_database.contracts import Dependency, CPE, CVE, Version, Vulnerability
from core.graph_database.base import BaseGraphInterface


class InMemoryGraph(BaseGraphInterface):
    def __init__(self):
        self._code_entities = {}  # {package_identifier: **props}
        self._cve_entities = {}  # {cve_id: CVE}
        self._cpe_relationships = {}  # {package_identifier: {version_key: {cve_id, ...}, ...}}
        self._dep_relationships = {}  # {(package_identifier, version_string): {dependency_name: (type, {version_key, ...})}}

    def get_cve_info(self, cve: str) -> CVE:
        return self._cve_entities.get(cve)

    def get_package_dependencies(self, package_identifier: str, version: str) -> Iterable[Dependency]:
        hash_key = package_identifier, version
        for dependency_name, (dependency_type, versions) in self._dep_relationships.get(hash_key, {}).items():
            for version_key in versions:
                yield Dependency(dependency_name, Version.from_key(version_key), dependency_type)

    def insert_package_node(self, package_identifier: str, package_type: str) -> None:
        pass  # for dev purposes we don't need this method

    def insert_dependencies_for_package(
        self, package_identifier: str, version: str, dependencies: List[Dependency]
    ):
        hash_key = package_identifier, version
        if hash_key not in self._dep_relationships:
            self._dep_relationships[hash_key] = {}

        for dependency in dependencies:
            if dependency.name not in self._dep_relationships[hash_key]:
                self._dep_relationships[hash_key][dependency.name] = (dependency.type, set())

            self._dep_relationships[hash_key][dependency.name][1].add(dependency.version.key)

    def get_package_vulnerabilities(self, package_identifier: str, version: str) -> Iterable[Vulnerability]:
        for version_key, cves in self._cpe_relationships.get(package_identifier, {}).items():
            affected_version = Version.from_key(version_key)
            if version in affected_version:
                for cve in cves:
                    yield Vulnerability(package_identifier, affected_version, cve)

    def insert_cve_affected_software(self, cve: CVE, cpe_list: List[CPE]) -> None:
        self._cve_entities[cve.name] = cve

        for cpe in cpe_list:
            if cpe.affected_software not in self._cpe_relationships:
                self._cpe_relationships[cpe.affected_software] = {}

            if cpe.version.key not in self._cpe_relationships[cpe.affected_software]:
                self._cpe_relationships[cpe.affected_software][cpe.version.key] = set()

            self._cpe_relationships[cpe.affected_software][cpe.version.key].add(cve.name)
