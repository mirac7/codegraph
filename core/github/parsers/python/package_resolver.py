from functools import lru_cache
from time import time
from typing import Dict
from requests import get
from lxml.html import fromstring, Element
from core.graph_database.contracts import Version


def timed_cache(target):
    @lru_cache(1048576)
    def cached(_ttl, *args, **kwargs):
        return target(*args, **kwargs)

    def modified(*args, **kwargs):
        ttl = int(time()/86400)
        return cached(ttl, *args, **kwargs)

    return modified


@timed_cache
def get_available_versions(package_name: str) -> Dict[str, str]:
    document: Element = fromstring(get(f"https://pypi.org/simple/{package_name}/").content)
    try:
        body = list(document)[1]
    except IndexError:
        return {}  # PyPI cannot resolve this package name

    all_versions = {
        element.text[len(package_name)+1:-7]: element.get("href").split("#")[0]  # strip id
        for element in body if element.tag == "a" and element.text.endswith(".tar.gz")
    }
    return all_versions


def resolve_best_version_url(package_name: str, target: Version):
    all_versions = get_available_versions(package_name)
    ordered = sorted(list(all_versions), reverse=True)  # resolve latest version first
    for version in ordered:
        if version in target:
            return version, all_versions[version]
    return None, None
