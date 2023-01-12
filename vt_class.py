import base64, json, os, datetime, requests
import time
from threading import Lock
from vt_url_detailes import VTurlDetails
from concurrent.futures import ThreadPoolExecutor
import errors_dict


class VTAnalyzer:

    def __init__(self):
        self._cache: dict[str: VTurlDetails] = {}
        self.__lock = Lock()
        with open(os.environ['VT_API']) as fh:
            self._key = json.load(fh)['VT_API']
        self._scan_header = {
            "accept": "application/json",
            "x-apikey": self._key,
            "content-type": "application/x-www-form-urlencoded"
        }
        self._analysis_header = {
            "accept": "application/json",
            "x-apikey": self._key
        }


    def _url_to_base64(self, url: str):
        return base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")

    def chack_status_code(self, response):
        """
        chack the status code of the request -> True if under 200 else False
        :param response: the result of the response
        :return: bool
        """
        return False if response.status_code >= 400 else True

    def add_to_cache(self, response_json: dict, url):
        """
        get the result of the request in dict and enter the information to VTurlDetails class and save in the cache
        :param response_json: dict of the result of the request
        :return:
        """
        vt_details = VTurlDetails(response_json['data']['attributes']['last_analysis_date'],
                                   response_json['data']['attributes']['last_analysis_stats']['harmless'],
                                   response_json['data']['attributes']['last_analysis_stats']['malicious'],
                                   response_json['data']['attributes']['last_analysis_stats']['suspicious'],
                                   response_json['data']['attributes']['last_analysis_stats']['undetected'],
                                   url)
        self._cache[url] = vt_details

    def get_reputation_for_single_url(self, url: str):
        # return the url in base64
        url_id = self._url_to_base64(url)

        url_re = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        return requests.get(url_re, headers=self._analysis_header)

        # response = requests.get(url_re, headers=self._analysis_header)
        #
        # response_json = response.json()
        #
        # # if there are an error it will return to futures the description
        # if not self.chack_status_code(response):
        #     return errors_dict.errors[response_json['error']['code']]
        #
        # self.add_to_cache(response_json, url)
        #
        # # response = requests.get(url, headers=headers)
        # return self._cache[url]

    def chack_day_scan(self,last_analysis_date, day):
        ts = last_analysis_date
        lad = datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        days_analysis = datetime.datetime.utcnow() - datetime.datetime.strptime(lad, '%Y-%m-%d %H:%M:%S')
        return day > days_analysis


    def cache_found_url(self, url: str, day_scan: datetime.timedelta):
        if url in self._cache:
            if not self.chack_day_scan(self._cache[url].last_analysis_date, day_scan):
                self.scan_url(url)
            return True
        return False

    def scan_url_requests(self, url):
        """
        send a post request for new scan
        """
        url = "https://www.virustotal.com/api/v3/urls"
        # payload = "url=https://www.clalit.co.il/"
        response = requests.post(url, data=f"url={url}", headers=self._scan_header)

    def scan_url(self, url):
        """
        function that scan -> post and get reputation about url
        """
        self.scan_url_requests(url)

        # sending requests until the analysis is finished
        while True:
            response = self.get_reputation_for_single_url(url)
            if response.status_code == 200:
                break
            time.sleep(0.1)

        self.add_to_cache(response.json(), url)
        return self._cache[url]

    def reputation_flow(self, url: str, scan: bool, day_scan: datetime.timedelta):
        # force scan
        if scan:
            return self.scan_url(url)
            # self.scan_url_requests(url)
            #
            # # sending requests until the analysis is finished
            # while True:
            #     response = self.get_reputation_for_single_url(url)
            #     if response.status_code == 200:
            #         break
            #     time.sleep(0.1)
            #
            # self.add_to_cache(response.json(), url)
            # return self._cache[url]

        else:
            if self.cache_found_url(url, day_scan):
                return self._cache[url]

            # TODO: do the get reputation and if the error is 404 I need to scan and then send another request
            response = self.get_reputation_for_single_url(url)
            # if there are an error it will return to futures the description
            if not self.chack_status_code(response):
                return errors_dict.errors[response.json()['error']['code']]

            self.add_to_cache(response.json(), url)
            return self._cache[url]


    @property
    def cache(self):
        return self._cache

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        self._key = value


class UrlUserSelection(VTAnalyzer):

    def __init__(self, url: str, scan: bool = False, apikey: str = None, day: int = 182):
        super().__init__()
        self._url = url.split(",")
        self._scan = scan
        self._apikey = apikey
        self._days_before_rescan = datetime.timedelta(days=day)

    def run(self):
        if self._apikey is not None:
            self.key = self._apikey

        with ThreadPoolExecutor(max_workers= 10) as executor:
            # futures =
            pass



        pass