from requests import get, RequestException
from datetime import date, timedelta
from time import sleep, time
from core.configuration import env_configuration
from core.graph_database.contracts import CVE, CPE, Version


class NVDSync:
    def __init__(self):
        self._graphdb_client = env_configuration.graphdb_factory()

    def _extract_cpe(self, cve, root):
        for child in root["children"]:
            yield from self._extract_cpe(cve, child)

        for match in root["cpe_match"]:
            affected_software, version = match["cpe23Uri"].split(":")[4:6]
            version_constraints = []

            if version not in ("*", "-", ""):
                version_constraints.append(("==", version))

            for key, operator in [
                ("versionEndIncluding", "<="), ("versionEndExcluding", "<"),
                ("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
            ]:
                if key in match:
                    version_constraints.append((operator, match[key]))

            yield CPE(cve, affected_software, Version(*version_constraints))

    def _fetch_cves(self, only_recent=False):
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=2000"
        if only_recent:
            start = (date.today()-timedelta(days=7)).strftime("%Y-%m-%d")
            end = (date.today()+timedelta(days=1)).strftime("%Y-%m-%d")
            url += f"&modStartDate={start}T00:00:00:000%20UTC%2B00:00&modEndDate={end}T00:00:00:000%20UTC%2B00:00"

        start_index, total_results = 0, 9999
        while start_index < total_results:
            try:
                response = get(f"{url}&startIndex={start_index}")
            except RequestException as e:
                print("Error", e.__class__.__name__, e.args)
                sleep(5)
                continue

            if response.status_code != 200:
                print("Error", response.status_code)
                print(response.content)
                sleep(5)
                continue

            json = response.json()

            for item in json["result"]["CVE_Items"]:
                name = item["cve"]["CVE_data_meta"]["ID"]

                cvss_v2_score = item["impact"].get("baseMetricV2", {"cvssV2": {"baseScore": None}})["cvssV2"]["baseScore"]
                cvss_v3_score = item["impact"].get("baseMetricV3", {"cvssV3": {"baseScore": None}})["cvssV3"]["baseScore"]
                publish_date = date.fromisoformat(item["publishedDate"][:10])

                description = ""
                for index, description_data in enumerate(item["cve"]["description"]["description_data"]):
                    if index == 0 or description_data["lang"] == "en":
                        description = description_data["value"]

                if "configurations" in item:
                    cpes = [cpe for node in item["configurations"]["nodes"] for cpe in self._extract_cpe(name, node)]
                else:
                    cpes = []  # do we even care about that cve at this point?

                yield CVE(name, description, cvss_v2_score, cvss_v3_score, publish_date), cpes

            total_results = json["totalResults"]
            start_index += 2000
            print(f"Synced {min(start_index, total_results)}/{total_results}")

    def sync_recent(self) -> None:
        for cve, cpe_list in self._fetch_cves(only_recent=True):
            self._graphdb_client.insert_cve_affected_software(cve, cpe_list)

    def sync_all(self) -> None:
        for cve, cpe_list in self._fetch_cves(only_recent=False):
            self._graphdb_client.insert_cve_affected_software(cve, cpe_list)


def run_sync_forever(load_history=True):
    sync = NVDSync()
    if load_history:
        sync.sync_all()
    else:
        sync.sync_recent()

    while True:
        sleep(-time() % env_configuration.nvd_sync_frequency)
        try:
            sync.sync_recent()
        except Exception as e:
            print(f"NVD sync failed - {e.__class__.__name__}{e.args}")
