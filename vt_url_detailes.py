import datetime


class VTurlDetails:

    def __init__(self, last_analysis_date: datetime, harmless: int, malicious: int, suspicious: int, undetected: int):
        self._last_analysis_date = last_analysis_date
        self._undetected = undetected  # harmless-malicious-suspicious>20 - good
        self._suspicious = suspicious
        self._malicious = malicious
        self._harmless = harmless


    @property
    def last_analysis_date(self):
        return self._last_analysis_date
    
    @last_analysis_date.setter
    def last_analysis_date(self, analysis_date: datetime):
        self._last_analysis_date = analysis_date

    @property
    def undetected(self):
        return self._undetected

    @undetected.setter
    def undetected(self, value: int):
        self._undetected = value

    @property
    def suspicious(self):
        return self._suspicious

    @suspicious.setter
    def suspicious(self, value: int):
        self._suspicious = value

    @property
    def malicious(self):
        return self._malicious

    @malicious.setter
    def malicious(self, value: int):
        self._malicious = value

    @property
    def harmless(self):
        return

    @harmless.setter
    def harmless(self, value):
        pass
    

























