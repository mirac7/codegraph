from abc import ABCMeta, abstractmethod
from typing import Iterable, List
from core.graph_database.contracts import Dependency, CPE, CVE, Vulnerability


class BaseGraphInterface(metaclass=ABCMeta):
    """ Abstract interface for all parsers """

    @abstractmethod
    def get_cve_info(self, cve: str) -> CVE:
        pass

    @abstractmethod
    def get_package_dependencies(self, package_identifier: str, version: str) -> Iterable[Dependency]:
        pass

    @abstractmethod
    def insert_package_node(self, package_identifier: str, package_type: str) -> None:
        pass

    @abstractmethod
    def insert_dependencies_for_package(
        self, package_identifier: str, version: str, dependencies: List[Dependency]
    ) -> None:
        pass

    @abstractmethod
    def get_package_vulnerabilities(self, package_identifier: str, version: str) -> Iterable[Vulnerability]:
        pass

    @abstractmethod
    def insert_cve_affected_software(self, cve: CVE, cpe_list: List[CPE]) -> None:
        pass
