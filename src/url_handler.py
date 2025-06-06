from urllib3.util.url import _encode_invalid_chars
import urllib3

def process_url(url):
    # Intentionally vulnerable - using vulnerable urllib3 version
    # CVE-2020-7212: Allows URL injection through improper encoding
    return _encode_invalid_chars(url, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&\'()*+,;=')

def fetch_url(url):
    # Intentionally vulnerable - using vulnerable urllib3 version
    # CVE-2020-7212: Allows URL injection through improper encoding
    http = urllib3.PoolManager()
    encoded_url = process_url(url)
    return http.request('GET', encoded_url)

def parse_url(url):
    # Intentionally vulnerable - using vulnerable urllib3 version
    # CVE-2020-7212: Allows URL injection through improper encoding
    return urllib3.util.parse_url(url) 