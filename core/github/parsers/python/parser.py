from json import JSONDecodeError, loads
from os.path import join
from re import findall
from typing import Iterable
# noinspection PyCompatibility,PyProtectedMember
from pip._vendor.pkg_resources import RequirementParseError, parse_requirements as pip_parse_requirements
from toml import TomlDecodeError
from core.github.parsers.base import BaseParser
from core.github.parsers.python.pipfile import Pipfile
from core.graph_database.contracts import Dependency, Version


class PythonParser(BaseParser):
    def parse_file_for_dependencies(self, path: str, filename: str) -> Iterable[Dependency]:
        yield from self._parse_requirements_file(path, filename)
        yield from self._parse_pipfile(path, filename)
        yield from self._parse_pipfile_lock(path, filename)

    def _parse_requirements_file(self, path: str, filename: str) -> Iterable[Dependency]:
        if ("requirements" in filename and filename.endswith(".txt")) or path.split("/")[-1] == "requirements":
            yield from self._resolve_requirements(source=self.read_source(path, filename))

    def _parse_pipfile(self, path: str, filename: str) -> Iterable[Dependency]:
        if filename.lower() == "pipfile":
            try:
                lock_output = loads(Pipfile.load(join(path, filename)).lock())
                output = self._resolve_pipfile_lock_data(lock_output)
                yield from output
            except TomlDecodeError:
                pass  # not a valid Pipfile

    def _parse_pipfile_lock(self, path: str, filename: str) -> Iterable[Dependency]:
        if filename.lower() == "pipfile.lock":
            try:
                lock_output = loads(self.read_source(path, filename))
                output = self._resolve_pipfile_lock_data(lock_output)
                yield from output
            except JSONDecodeError:
                pass  # not a valid Pipfile lock file

    def _resolve_pipfile_lock_data(self, lock_data: dict) -> Iterable[Dependency]:
        try:
            all_packages = {**lock_data["default"], **lock_data["develop"]}
            requirements = [Dependency(name=package, version=self.resolve_version_expression(
                package_data if isinstance(package_data, str) else package_data.get("version", "*")
            ), dependency_type="python-package") for package, package_data in all_packages.items()]
            yield from requirements
        except KeyError:
            pass  # not a valid Pipfile lock file

    def _resolve_requirements(self, source: str) -> Iterable[Dependency]:
        try:
            requirements = []
            for requirement in pip_parse_requirements(source):
                requirements.append(Dependency(
                    name=requirement.key,
                    version=self.resolve_version_expression(requirement.specs),
                    dependency_type="python-package"
                ))

                for extra in requirement.extras:
                    pass  # todo: resolve requirement.extras
            yield from requirements
        except (SyntaxError, RequirementParseError):
            # pip install would have failed for this file and aborted everything,
            # ignore any successfully parsed requirements
            pass

    @staticmethod
    def resolve_version_expression(expr):
        if not expr or expr == "*":
            return Version()

        if isinstance(expr, str):
            # this may fail if expression is malformed, but at this point we are trusting the parser has done their job
            conditions = []
            for subexpr in expr.split(","):
                regex_match = findall(r"^([=~!<>]+) *([\d.A-Za-z]+)$", subexpr.strip())
                conditions.append(regex_match[0])
            return Version(*conditions)

        return Version(*expr)  # trust that the input was properly formatted already
