from datetime import date
from typing import Tuple, Union


class Version:
    _version_operators = {
        '==': lambda x, y: x == y,
        '===': lambda x, y: x == y,
        '~=': lambda x, y: x == y or x > y,
        '!=': lambda x, y: x != y,
        '<': lambda x, y: x < y,
        '<=': lambda x, y: x == y or x < y,
        '>': lambda x, y: x > y,
        '>=': lambda x, y: x == y or x > y,
    }

    def __init__(self, *constraints: Tuple[str, str]):
        self.constraints = constraints

    @property
    def key(self):  # packing in database, hashing, etc.
        if not hasattr(self, "_key"):
            self._key = ",".join(f"{operator}:{version}" for operator, version in sorted(self.constraints))
        return self._key

    def __eq__(self, other: "Version"):
        return self.key == other.key

    def __hash__(self):
        return hash(self.key)

    # check whether version: str encompassed by this Version object
    def __contains__(self, item: Union[str, "Version"]):
        if isinstance(item, str):
            for operator, version in self.constraints:
                if not self._version_operators[operator](item, version):
                    return False
            return True

    @classmethod
    def from_key(cls, key):
        return cls(*(tuple(item.split(":")) for item in key.split(",")) if key else [])


class Dependency:
    def __init__(self, name: str, version: Version, dependency_type):
        self.name, self.version, self.type = name, version, dependency_type

    # deduplication support
    def __eq__(self, other: "Dependency"):
        return self.name == other.name and self.version == other.version

    def __hash__(self):
        return hash((self.name, self.version))


class Vulnerability:
    def __init__(self, name: str, version: Version, cve: str):
        self.name, self.version, self.cve = name, version, cve


class CVE:
    def __init__(self, name: str, description: str, cvss_v2_score: float, cvss_v3_score: float, publish_date: date):
        self.name, self.description, self.cvss_v2_score, self.cvss_v3_score, self.publish_date = \
            name, description, cvss_v2_score, cvss_v3_score, publish_date


class CPE:
    def __init__(self, cve_name: str, affected_software: str, version: Version):
        self.cve_name, self.affected_software, self.version = cve_name, affected_software, version
