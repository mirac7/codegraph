from abc import ABCMeta, abstractmethod
from os.path import join
from typing import Iterable
from core.graph_database.contracts import Dependency


class BaseParser(metaclass=ABCMeta):
    """ Abstract interface for all parsers """

    @abstractmethod
    def parse_file_for_dependencies(self, path: str, filename: str) -> Iterable[Dependency]:
        pass

    @staticmethod
    def read_source(*file_segments: str) -> str:
        return open(join(*file_segments), encoding="utf-8", errors="ignore").read()
