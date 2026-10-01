import json
import re

import requests
from requests.exceptions import RequestException


def parse_headers(raw: str) -> dict:
    text = raw.strip()
    if not text:
        return {}

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (json.JSONDecodeError, ValueError):
        pass

    m = re.search(r"=\s*(\{.*\})\s*$", text, re.DOTALL)
    body = m.group(1) if m else text

    start = body.find("{")
    end = body.rfind("}")
    if start != -1 and end != -1 and end > start:
        body = body[start : end + 1]

    headers = {}
    for km, vm in re.findall(
        r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']*)["\']', body
    ):
        headers[km] = vm
    return headers


_HOP_BY_HOP = {
    "accept-encoding",
    "content-length",
    "host",
    "connection",
    "transfer-encoding",
}


def do_request(method: str, url: str, headers: dict, body=None, stream=False):
    clean = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}
    return requests.request(
        method, url, headers=clean, data=body, timeout=30,
        allow_redirects=True, stream=stream,
    )


def perform_request(method: str, url: str, headers: dict, body=None) -> dict:
    try:
        resp = do_request(method, url, headers, body)
        return {
            "ok": True,
            "status_code": resp.status_code,
            "resp_headers": json.dumps(dict(resp.headers), indent=2, ensure_ascii=False),
            "resp_body": resp.text,
            "error": None,
        }
    except RequestException as exc:
        return {
            "ok": False,
            "status_code": None,
            "resp_headers": "",
            "resp_body": "",
            "error": str(exc),
        }
