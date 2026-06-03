# -*- coding: utf-8 -*-
"""
Dynamic URL Analyzer
+ Auto Update
+ Self Learning
+ VirusTotal
"""

import re
import base64
import requests
from urllib.parse import urlparse
from typing import Dict, Any
import os

class URLAnalyzer:

    # 🔥 API KEY LANGSUNG DI SINI
    API_KEY = os.getenv("VT_API_KEY")


    def __init__(self):

        self.SUSPICIOUS_KEYWORDS = [
            'login',
            'verify',
            'secure',
            'account',
            'bank',
            'password'
        ]

        self.URL_SHORTENERS = [
            'bit.ly',
            'tinyurl.com',
            't.co'
        ]

        self.SUSPICIOUS_TLDS = [
            'tk',
            'ml',
            'ga',
            'cf'
        ]

        self.PHISHING_LIST = []
        self.analysis_result = {}

        # 🔥 AUTO UPDATE
        self._auto_update()

    # -----------------------------
    # AUTO UPDATE
    # -----------------------------
    def _auto_update(self):
        self._update_shorteners()
        self._update_phishing_list()
        self._self_learning_keywords()

    def _update_shorteners(self):

        try:
            url = "https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list"

            res = requests.get(url, timeout=5)

            if res.status_code == 200:
                self.URL_SHORTENERS = res.text.splitlines()

        except:
            pass

    def _update_phishing_list(self):

        try:
            url = "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter.txt"

            res = requests.get(url, timeout=5)

            if res.status_code == 200:
                self.PHISHING_LIST = res.text.splitlines()

        except:
            self.PHISHING_LIST = []

    # -----------------------------
    # SELF LEARNING
    # -----------------------------
    def _self_learning_keywords(self):

        try:
            words = []

            for url in self.PHISHING_LIST[:500]:

                found = re.findall(r'[a-zA-Z]{4,}', url.lower())

                words.extend(found)

            freq = {}

            for w in words:
                freq[w] = freq.get(w, 0) + 1

            learned = [k for k, v in freq.items() if v > 5]

            self.SUSPICIOUS_KEYWORDS.extend(learned)

        except:
            pass

    # -----------------------------
    # MAIN ANALYSIS
    # -----------------------------
    def analyze(self, url: str) -> Dict[str, Any]:

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)

        self.analysis_result = {
            'original_url': url,
            'length': len(url),
            'is_shortened': self._check_if_shortened(parsed.netloc),
            'subdomain_count': self._count_subdomains(parsed.netloc),
            'suspicious_chars': self._check_suspicious_chars(url),
            'protocol_type': self._analyze_protocol(parsed.scheme),
            'is_suspicious_tld': self._is_suspicious_tld(parsed.netloc),
            'has_suspicious_keywords': self._check_keywords(url),
            'has_ip_address': self._has_ip(parsed.netloc),
            'has_port': ':' in parsed.netloc,
            'has_encoded_chars': bool(re.search(r'%[0-9A-Fa-f]{2}', url)),
            'has_double_extension': bool(re.search(r'\.\w+\.\w+$', parsed.path))
        }

        vt = self._check_virustotal(url)

        if vt is None:
            raise Exception("VirusTotal failed")

        self.analysis_result['virustotal'] = vt

        return self.analysis_result

    # -----------------------------
    # VIRUSTOTAL
    # -----------------------------
    def _check_virustotal(self, url: str):

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": self.API_KEY
        }

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        try:
            res = requests.get(
                vt_url,
                headers=headers,
                timeout=10
            )

            if res.status_code == 200:

                data = res.json()

                stats = data["data"]["attributes"]["last_analysis_stats"]

                return {
                    "malicious": stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "harmless": stats["harmless"]
                }

            elif res.status_code == 404:

                requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url}
                )

                return {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0
                }

        except:
            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0
            }

        return None

    # -----------------------------
    # HELPERS
    # -----------------------------
    def _check_if_shortened(self, netloc):

        return any(
            s in netloc.lower()
            for s in self.URL_SHORTENERS
        )

    def _count_subdomains(self, netloc):

        parts = netloc.split('.')

        return len(parts) - 2 if len(parts) >= 3 else 0

    def _check_suspicious_chars(self, url):

        found = re.findall(
            r'[@#$%^&*()+=!\[\]{}|\\:;<>,?~`"\']',
            url
        )

        return {
            'count': len(found)
        }

    def _analyze_protocol(self, scheme):

        return {
            'is_secure': scheme == 'https'
        }

    def _is_suspicious_tld(self, netloc):

        tld = netloc.split('.')[-1]

        return tld in self.SUSPICIOUS_TLDS

    def _check_keywords(self, url):

        found = [
            k for k in self.SUSPICIOUS_KEYWORDS
            if k in url.lower()
        ]

        return {
            'count': len(found)
        }

    def _has_ip(self, netloc):

        return bool(
            re.match(r'\d+\.\d+\.\d+\.\d+', netloc)
        )

    # -----------------------------
    # FINAL SCORE
    # -----------------------------
    def get_risk_score(self):

        r = self.analysis_result

        if not r:
            return 0

        score = 0

        if r['length'] > 100:
            score += 10

        if r['is_shortened']:
            score += 20

        if r['subdomain_count'] > 2:
            score += 15

        score += r['suspicious_chars']['count'] * 2

        if not r['protocol_type']['is_secure']:
            score += 10

        if r['is_suspicious_tld']:
            score += 20

        score += r['has_suspicious_keywords']['count'] * 4

        if r['has_ip_address']:
            score += 25

        if r['has_port']:
            score += 10

        if r['has_encoded_chars']:
            score += 10

        if r['has_double_extension']:
            score += 25

        vt = r.get('virustotal')

        if vt:
            score += min(
                (vt['malicious'] * 10) +
                (vt['suspicious'] * 5),
                50
            )

        return max(0, min(score, 100))
