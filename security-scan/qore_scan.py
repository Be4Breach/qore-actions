#!/usr/bin/env python3
"""QORE scan for CI/CD: start a scan of a repository and fail the build on its verdict.

Standard library only, so it runs on any CI runner with Python 3.8+.

    QORE_API_KEY=be4ci_... python qore_scan.py --repo owner/name

The API key is read from the QORE_API_KEY environment variable only (a command-line argument would show in
the process list). The scan runs through a GitHub connector your QORE administrator already set up (QORE
picks the one that can read the repository), so no GitHub token is needed here. The pass / fail decision is
made by the QORE server. The API address defaults to QORE's hosted service; set --api-url (or QORE_API_URL)
only for a self-hosted installation.

Exit codes: 0 pass, 1 build should fail (findings), 2 error (scan failed, timed out, or the API refused).
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

EXIT_PASS, EXIT_FAIL, EXIT_ERROR = 0, 1, 2
DEFAULT_API_URL = "https://api.be4breach.com"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
USER_AGENT = "qore-scan-ci/1"
MAX_BACKOFF_SECONDS = 60


class QoreError(Exception):
    """Something that makes the run an error (exit 2), with a message safe to print."""


def normalize_api_url(url: str) -> str:
    """The API base URL. HTTPS only, except localhost for development: the key travels in a header."""
    url = (url or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise QoreError("--api-url must be an https:// URL.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise QoreError("--api-url is not a valid URL.")
    return url


def _request(method: str, url: str, key: str, body=None, timeout: int = 30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + key)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", USER_AGENT)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme validated above
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}"), resp.headers
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            payload = {}
        return exc.code, payload, exc.headers
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise QoreError("Could not reach the QORE API: %s" % type(exc).__name__)


def _detail(payload) -> str:
    detail = payload.get("detail") if isinstance(payload, dict) else None
    return detail if isinstance(detail, str) else "no further detail"


def start_scan(api_url, key, repo):
    code, payload, headers = _request("POST", api_url + "/api/ci/v1/scans", key, {"repo": repo})
    if code == 202:
        return payload
    if code == 401:
        raise QoreError("The QORE API key was rejected (invalid, revoked or expired).")
    if code == 403:
        raise QoreError("Access denied: %s" % _detail(payload))
    if code == 404:
        raise QoreError("Not found: %s" % _detail(payload))
    if code == 409:
        raise QoreError("A scan is already running for this repository. Retry when it finishes.")
    if code == 422:
        raise QoreError("The request was refused: %s" % _detail(payload))
    if code == 429:
        raise QoreError("%s Retry after %s seconds." % (_detail(payload), headers.get("Retry-After", "a while")))
    raise QoreError("The QORE API could not start the scan (HTTP %s): %s" % (code, _detail(payload)))


def wait_for_verdict(api_url, key, scan_id, fail_on, mode, timeout_s, poll_s, sleep=time.sleep, clock=time.monotonic):
    url = "%s/api/ci/v1/scans/%s?%s" % (api_url, urllib.parse.quote(scan_id, safe=""), urllib.parse.urlencode({"fail_on": fail_on, "mode": mode}))
    deadline = clock() + timeout_s
    backoff = poll_s
    while True:
        code, payload, headers = _request("GET", url, key)
        if code == 200:
            backoff = poll_s
            if payload.get("done"):
                return payload
        elif code in (429, 502, 503, 504):
            try:
                backoff = min(MAX_BACKOFF_SECONDS, max(backoff, int(headers.get("Retry-After") or 0), backoff * 2))
            except (TypeError, ValueError):
                backoff = min(MAX_BACKOFF_SECONDS, backoff * 2)
        elif code == 401:
            raise QoreError("The QORE API key was rejected while waiting for the scan.")
        else:
            raise QoreError("The QORE API returned HTTP %s while waiting: %s" % (code, _detail(payload)))
        if clock() + backoff >= deadline:
            raise QoreError("Timed out waiting for the scan (it keeps running; see the QORE portal).")
        sleep(backoff)


def exit_code_for(result) -> int:
    verdict = result.get("verdict")
    if verdict == "pass":
        return EXIT_PASS
    if verdict == "fail":
        return EXIT_FAIL
    return EXIT_ERROR


def render_summary(result) -> str:
    lines = ["## QORE security scan: %s" % str(result.get("verdict", "unknown")).upper(), ""]
    lines.append("Repository: `%s`  ·  run %s  ·  mode: %s  ·  fails on: %s" % (
        result.get("repo"), result.get("run_number") or "?", result.get("mode"), ", ".join(result.get("fail_on") or [])))
    if result.get("note"):
        lines += ["", "> " + str(result["note"])]
    counts = result.get("counts")
    if counts:
        new = result.get("new_counts") or {}
        lines += ["", "| Severity | Open | New in this scan |", "|---|---:|---:|"]
        for band in ("critical", "high", "medium", "low"):
            lines.append("| %s | %s | %s |" % (band.capitalize(), counts.get(band, 0), new.get(band, 0)))
    for reason in result.get("reasons") or []:
        lines.append("- **%s**" % reason)
    findings = result.get("findings") or []
    if findings:
        lines += ["", "| Severity | Type | Finding | Where |", "|---|---|---|---|"]
        for f in findings:
            flags = (" (new)" if f.get("new") else "") + (" (KEV)" if f.get("kev") else "")
            lines.append("| %s | %s | %s%s | %s |" % (f.get("severity"), f.get("type"), _md(f.get("id")), flags, _md(f.get("where"))))
    return "\n".join(lines) + "\n"


def _md(value) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")[:200]


def _write_github_files(result):
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(render_summary(result))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for name in ("scan_id", "run_number", "verdict"):
                value = str(result.get(name) or "")
                if "\n" not in value:
                    fh.write("%s=%s\n" % (name, value))


def parse_args(argv):
    p = argparse.ArgumentParser(description="Run a QORE scan and fail the build on its verdict.")
    p.add_argument("--api-url", default=os.environ.get("QORE_API_URL", "").strip() or DEFAULT_API_URL,
                   help="QORE base URL, only for self-hosted installations (or QORE_API_URL); default: %s" % DEFAULT_API_URL)
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/name (default: GITHUB_REPOSITORY)")
    p.add_argument("--fail-on", default="critical,kev", help="comma list of critical,high,medium,low,kev (default critical,kev)")
    p.add_argument("--mode", choices=("new", "all"), default="new", help="fail on findings new in this scan, or on all open ones")
    p.add_argument("--timeout-minutes", type=int, default=20)
    p.add_argument("--poll-seconds", type=int, default=10)
    p.add_argument("--no-wait", action="store_true", help="start the scan and exit without waiting for the verdict")
    return p.parse_args(argv)


def main(argv=None, sleep=time.sleep) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    key = os.environ.get("QORE_API_KEY", "").strip()
    try:
        if not key:
            raise QoreError("QORE_API_KEY is not set.")
        if not REPO_RE.fullmatch(args.repo or ""):
            raise QoreError("--repo must be 'owner/name'.")
        if not 1 <= args.timeout_minutes <= 120 or not 2 <= args.poll_seconds <= 120:
            raise QoreError("--timeout-minutes must be 1-120 and --poll-seconds 2-120.")
        api_url = normalize_api_url(args.api_url)

        started = start_scan(api_url, key, args.repo)
        print("QORE scan started: %s (run %s)" % (started.get("repo"), started.get("run_number") or "?"), flush=True)
        if args.no_wait:
            return EXIT_PASS
        result = wait_for_verdict(api_url, key, started["scan_id"], args.fail_on, args.mode,
                                  args.timeout_minutes * 60, args.poll_seconds, sleep=sleep)
    except QoreError as exc:
        print("QORE: %s" % str(exc).replace(key, "***") if key else "QORE: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    print(render_summary(result))
    _write_github_files(result)
    return exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())
