from codecs import encode
from typing import Iterable, Optional
from git import Repo
from os import urandom, walk
from shutil import rmtree
from core.graph_database.contracts import Dependency


# this wrapper is used for any non-repo source tree as well, we're reusing helpful interface
class Repository:
    _path_root = "tmp/"

    @classmethod
    def from_url(cls, url: str) -> "Repository":
        return Repository(url.split("/")[-1], url, "", encode(urandom(16), "hex").decode())

    @classmethod
    def from_path(cls, name: str, version: str, path: str) -> "Repository":
        return Repository(name, None, version, path)

    def __init__(self, name: str, url: Optional[str], version: str, path: str):
        self.name, self.version, self._url = name, version, url
        self._path = self._path_root + path

    def clone(self) -> None:
        Repo.clone_from(self._url, self._path, depth=1)  # shallow clone
        # todo: set version from commit

    def cleanup(self) -> None:
        rmtree(self._path, ignore_errors=True)

    def parse_direct_dependencies(self) -> Iterable[Dependency]:
        from core.github.parsers import all_parsers
        # importing locally to prevent cyclic dependencies

        parsers = [parser() for parser in all_parsers]
        for path, _, files in walk(self._path):
            for filename in files:
                for parser in parsers:
                    yield from parser.parse_file_for_dependencies(path, filename)

    @property
    def can_clone(self):
        return self._url is not None

    def __del__(self):
        self.cleanup()
