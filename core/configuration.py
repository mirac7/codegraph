from core.graph_database.base import BaseGraphInterface
from collections import Callable
from importlib import import_module
from sys import argv
from yaml import load, Loader


class Configuration:
    def __init__(self, config_filepath: str):
        yaml = load(open(config_filepath), Loader=Loader)

        graphdb_module, graphdb_class = yaml["graphdb"]["module"], yaml["graphdb"]["class"]
        graphdb_factory: Callable[..., BaseGraphInterface] = \
            getattr(import_module(f"core.graph_database.{graphdb_module}"), graphdb_class)
        graphdb_args = yaml["graphdb"].get("args") or {}
        self.graphdb_factory = lambda: graphdb_factory(**graphdb_args)

        self.report_cache_ttl = yaml["graph_cache"]["ttl"]
        self.nvd_sync_frequency = yaml["nvd"]["sync_frequency"]


class NoConfiguration:
    @property
    def config_unset(self):
        raise EnvironmentError("Configuration file unset")

    graphdb_factory = report_cache_ttl = nvd_sync_frequency = config_unset


env_configuration = Configuration(argv[1]) if len(argv) > 1 else NoConfiguration()
