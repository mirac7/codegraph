from typing import Iterable
from core.configuration import env_configuration
from core.github.parsers.python.package_resolver import resolve_best_version_url
from core.github.repository import Repository
from core.graph_database.contracts import Version
from core.util import download_and_unpack_tar


def process_python_package(graph_builder, package: str, version: Version) -> Iterable[str]:
    yield f"Resolving {package}..."

    best_version, url = resolve_best_version_url(package, version)
    if not best_version:
        return  # did not resolve, false positive?

    from core.graph_database.memgraph import Memgraph
    db: Memgraph = env_configuration.graphdb_factory()

    # todo: we should differentiate between cache miss and no dependencies, this is too slow
    if dependencies := list(db.get_package_dependencies(package, best_version)):
        graph_builder.include_dependencies(package, "python-package", dependencies)
        return

    yield f"Downloading {package}..."
    output = download_and_unpack_tar(url)

    yield f"Scanning {package} for vulnerabilities..."
    repository = Repository.from_path(package, best_version, output)
    graph_builder.include_repo(repository)

