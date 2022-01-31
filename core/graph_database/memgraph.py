from time import sleep
from mgclient import Node, connect, Error as MemgraphError
from datetime import date
from typing import Iterable, List
from core.graph_database.base import BaseGraphInterface
from core.graph_database.contracts import CPE, CVE, Dependency, Version, Vulnerability


_query_cve_info = 'MATCH (v) WHERE (v:Cve AND v.name = "{cve}") RETURN v;'
_query_vulnerabilities = (
    'MATCH (cve)-[affects]-(code) '
    'WHERE (cve:Cve AND code:Code AND code.name = "{code}") '
    'RETURN cve, affects, code;'
)
_query_dependencies = (
    'MATCH (root)-[dep]-(child) '
    'WHERE (root:Code AND root.name = "{root}" AND dep.root_version = "{version}" AND child:Code) '
    'RETURN dep, child;'
)
_query_insert_cve = (
    'MERGE (cve:Cve {{ name: "{name}" }}) '
    'ON CREATE SET cve.description="{description}", '
    'cve.cvss_v2_score="{cvss_v2_score}", '
    'cve.cvss_v3_score="{cvss_v3_score}", '
    'cve.publish_date="{publish_date}";'
)
_query_insert_package = 'MERGE (code:Code:Repo {{ name: "{name}" }});'
_query_insert_package_with_type = (
    'MERGE (code:Code:Repo {{ name: "{name}" }}) '
    'SET code.type = "{type}";'
)
_query_insert_cpe = (
    'MATCH (cve:Cve {{name: "{cve}" }}), (code:Code {{ name: "{code}" }}) '
    'MERGE (cve)-[:CPE {{ version: "{version}" }}]->(code);'
)
_query_insert_dependency = (
    'MATCH (root:Code {{ name: "{root}" }}), (child:Code {{ name: "{dependency}", type: "{type}" }}) '
    'MERGE (root)-[:DEP {{ root_version: "{root_version}", dependency_version: "{dependency_version}" }}]->(child);'
)


class Memgraph(BaseGraphInterface):
    def __init__(self, host, port):
        self._client = connect(host=host, port=port)
        self._client.autocommit = True

    def _execute(self, query: str, retry_until_success=False, **params) -> list:
        cursor = self._client.cursor()
        complete_query = query.format(**{key: self._escape(str(value)) for key, value in params.items()})
        if retry_until_success:
            while True:
                try:
                    cursor.execute(complete_query)
                    break
                except MemgraphError:
                    sleep(1)
        else:
            cursor.execute(complete_query)
        result = cursor.fetchall()
        cursor.close()
        return result

    @staticmethod
    def _escape(string: str) -> str:
        return string.replace("\\", "\\\\").replace("\"", "\\\"")

    @staticmethod
    def _construct_cve(cve_node: Node) -> CVE:
        return CVE(
            name=cve_node.properties["name"],
            description=cve_node.properties["description"],
            cvss_v2_score=cve_node.properties["cvss_v2_score"],
            cvss_v3_score=cve_node.properties["cvss_v3_score"],
            publish_date=date(*(int(f) for f in cve_node.properties["publish_date"].split("-")))
        )

    def get_cve_info(self, cve: str) -> CVE:
        if result := self._execute(_query_cve_info, cve=cve):
            return self._construct_cve(cve_node=result[0][0])

    def get_package_dependencies(self, package_identifier: str, version: str) -> Iterable[Dependency]:
        result = self._execute(_query_dependencies, root=package_identifier, version=version)
        for depends, child in result:
            yield Dependency(
                name=child.properties["name"],
                version=Version.from_key(depends.properties["dependency_version"]),
                dependency_type=child.properties["type"]
            )

    def insert_package_node(self, package_identifier: str, package_type: str) -> None:
        self._execute(
            _query_insert_package_with_type, name=package_identifier, type=package_type, retry_until_success=True
        )

    def insert_dependencies_for_package(
        self, package_identifier: str, version: str, dependencies: List[Dependency]
    ):
        for dependency in dependencies:
            self._execute(
                _query_insert_package_with_type, name=dependency.name, type=dependency.type, retry_until_success=True
            )
            self._execute(
                _query_insert_dependency, root=package_identifier, dependency=dependency.name, type=dependency.type,
                root_version=version, dependency_version=dependency.version.key, retry_until_success=True
            )

    # todo: this is likely a non-issue, but we might want to move version filtering to memgraph?
    def get_package_vulnerabilities(self, package_identifier: str, version: str) -> Iterable[Vulnerability]:
        result = self._execute(_query_vulnerabilities, code=package_identifier)
        for cve, affects, code in result:
            affected_version = Version.from_key(affects.properties["version"])
            if version in affected_version:
                yield Vulnerability(package_identifier, affected_version, cve.properties["name"])

    def insert_cve_affected_software(self, cve: CVE, cpe_list: List[CPE]) -> None:
        self._execute(
            _query_insert_cve, publish_date=cve.publish_date.strftime("%Y-%m-%d"),
            **{attr: getattr(cve, attr) for attr in ("name", "description", "cvss_v2_score", "cvss_v3_score")},
            retry_until_success=True
        )
        all_affected_software = {cpe.affected_software for cpe in cpe_list}
        for name in all_affected_software:
            self._execute(_query_insert_package, name=name, retry_until_success=True)

        for cpe in cpe_list:
            self._execute(
                _query_insert_cpe, cve=cpe.cve_name, code=cpe.affected_software, version=cpe.version.key,
                retry_until_success=True
            )
