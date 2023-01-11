import base64
import json
import os
from threading import Lock
from vt_url_detailes import VTurlDetails
import requests


class VTAnalyzer:

    def __init__(self):
        self._cache: dict[str: VTurlDetails] = {}
        self.__lock = Lock()
        with open(os.environ['VT_API']) as fh:
            self._key = json.load(fh)

    def _url_to_base64(self, url: str):
        return base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")

    def get_url_reputation(self):
        pass

    def _get_reputation_for_single_url(self, url: str):
        url_id = self._url_to_base64(url)

        url_re = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": self._key['VT_API']
        }

        # response = requests.get(url, headers=headers)
        return requests.get(url, headers=headers)

    def cache_found_url(self, url: str):
        pass

    @property
    def cache(self):
        return self._cache


class UserSelection(VTAnalyzer):

    def __init__(self, url: list, scan: bool = False, apikey: str = None):
        super().__init__()
        self.url = url
        self.scan = scan
        self.apikey = apikey

    def run(self):
        pass