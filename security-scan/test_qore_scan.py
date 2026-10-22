"""qore_scan.py against a local fake QORE API.

Run with:  python -m pytest security-scan/test_qore_scan.py   (from the repository root)
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qore_scan  # noqa: E402

KEY = "be4ci_" + "k" * 43


class Fake:
    """What the fake server answers; tests set these."""
    start = (202, {"scan_id": "abc123", "repo": "acme/api", "run_number": 4})
    statuses = []   # successive GET answers (code, body, headers)
    seen = []       # (method, path, authorization, body)


def make_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, headers=None):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            Fake.seen.append(("POST", self.path, self.headers.get("Authorization"), body))
            self._send(*Fake.start[:2])

        def do_GET(self):
            Fake.seen.append(("GET", self.path, self.headers.get("Authorization"), None))
            code, body, *rest = Fake.statuses.pop(0) if len(Fake.statuses) > 1 else Fake.statuses[0]
            self._send(code, body, rest[0] if rest else None)

    return H


@pytest.fixture
def server(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), make_handler())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Fake.start = (202, {"scan_id": "abc123", "repo": "acme/api", "run_number": 4})
    Fake.statuses, Fake.seen = [], []
    monkeypatch.setenv("QORE_API_KEY", KEY)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    yield "http://127.0.0.1:%d" % srv.server_port
    srv.shutdown()


def run(url, *extra):
    return qore_scan.main(["--api-url", url, "--repo", "acme/api", "--poll-seconds", "2", *extra], sleep=lambda s: None)


DONE_PASS = {"done": True, "verdict": "pass", "repo": "acme/api", "run_number": 4, "mode": "new", "fail_on": ["critical", "kev"],
             "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0}, "new_counts": {}, "findings": [], "scan_id": "abc123"}
DONE_FAIL = dict(DONE_PASS, verdict="fail", reasons=["1 new critical finding"],
                 findings=[{"severity": "critical", "type": "sast", "id": "r|1", "where": "src/a.py:3", "new": True, "kev": False}])


def test_pass_exits_zero_and_sends_the_key_only_as_a_bearer_header(server):
    Fake.statuses = [(200, {"done": False, "status": "running"}), (200, DONE_PASS)]
    assert run(server) == qore_scan.EXIT_PASS
    method, path, auth, body = Fake.seen[0]
    assert (method, path, auth, body) == ("POST", "/api/ci/v1/scans", "Bearer " + KEY, {"repo": "acme/api"})
    assert KEY not in "".join(p for _, p, _, _ in Fake.seen)  # never in a URL
    assert "fail_on=critical%2Ckev" in Fake.seen[1][1] and "mode=new" in Fake.seen[1][1]


def test_a_failing_verdict_exits_one_and_the_summary_is_written(server, tmp_path, monkeypatch, capsys):
    summary, output = tmp_path / "sum.md", tmp_path / "out.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    Fake.statuses = [(200, DONE_FAIL)]
    assert run(server, "--fail-on", "critical", "--mode", "all") == qore_scan.EXIT_FAIL
    text = summary.read_text()
    assert "QORE security scan: FAIL" in text and "1 new critical finding" in text and "r\\|1" in text  # table-safe
    assert "verdict=fail" in output.read_text() and "scan_id=abc123" in output.read_text()
    assert "FAIL" in capsys.readouterr().out


def test_a_failed_scan_is_an_error_not_a_pass(server):
    Fake.statuses = [(200, {"done": True, "verdict": "error", "reasons": ["Scan failed."]})]
    assert run(server) == qore_scan.EXIT_ERROR


@pytest.mark.parametrize("code,fragment", [(401, "rejected"), (403, "Access denied"), (404, "Not found"), (409, "already running"),
                                           (422, "refused"), (429, "Retry after"), (500, "HTTP 500")])
def test_api_refusals_are_errors_with_a_clear_message(server, capsys, code, fragment):
    Fake.start = (code, {"detail": "nope"})
    assert run(server) == qore_scan.EXIT_ERROR
    err = capsys.readouterr().err
    assert fragment in err and KEY not in err


def test_no_wait_starts_the_scan_and_returns(server):
    assert run(server, "--no-wait") == qore_scan.EXIT_PASS
    assert [m for m, *_ in Fake.seen] == ["POST"]


def test_times_out_instead_of_waiting_forever(server):
    Fake.statuses = [(200, {"done": False, "status": "running"})]
    ticks = iter(range(0, 10_000, 30))  # a fake clock: 30 s per reading
    with pytest.raises(qore_scan.QoreError, match="Timed out"):
        qore_scan.wait_for_verdict(server, KEY, "abc123", "critical", "new", 120, 10, sleep=lambda s: None, clock=lambda: next(ticks))


def test_throttling_is_retried_with_backoff(server):
    Fake.statuses = [(429, {"detail": "slow down"}, {"Retry-After": "3"}), (200, DONE_PASS)]
    sleeps = []
    code = qore_scan.main(["--api-url", server, "--repo", "acme/api", "--poll-seconds", "2"], sleep=sleeps.append)
    assert code == qore_scan.EXIT_PASS and sleeps and sleeps[0] >= 3


@pytest.mark.parametrize("args,env_key", [
    (["--api-url", "https://x.example", "--repo", "bad"], KEY),                 # repo shape
    (["--api-url", "https://x.example", "--repo", "a/b\n"], KEY),
    (["--api-url", "http://x.example", "--repo", "a/b"], KEY),                  # plain http to a remote host
    (["--api-url", "https://user:pw@x.example", "--repo", "a/b"], KEY),         # credentials in the URL
    (["--api-url", "https://x.example", "--repo", "a/b"], ""),                  # no key
    (["--api-url", "https://x.example", "--repo", "a/b", "--timeout-minutes", "0"], KEY),
])
def test_bad_input_is_an_error_before_any_request(monkeypatch, args, env_key):
    monkeypatch.setenv("QORE_API_KEY", env_key)
    monkeypatch.setattr(qore_scan, "_request", lambda *a, **k: pytest.fail("no request expected"))
    assert qore_scan.main(args) == qore_scan.EXIT_ERROR


def test_exit_codes_follow_the_verdict():
    assert qore_scan.exit_code_for({"verdict": "pass"}) == 0
    assert qore_scan.exit_code_for({"verdict": "fail"}) == 1
    assert qore_scan.exit_code_for({"verdict": "error"}) == 2
    assert qore_scan.exit_code_for({}) == 2  # an answer without a verdict never passes the build


def _capture_start(monkeypatch):
    seen = {}

    def fake_start(api_url, key, repo):
        seen["api_url"] = api_url
        return {"scan_id": "abc123", "repo": repo, "run_number": 1}

    monkeypatch.setattr(qore_scan, "start_scan", fake_start)
    return seen


def test_the_api_address_defaults_to_the_hosted_service(monkeypatch):
    monkeypatch.setenv("QORE_API_KEY", KEY)
    monkeypatch.delenv("QORE_API_URL", raising=False)
    seen = _capture_start(monkeypatch)
    assert qore_scan.main(["--repo", "acme/api", "--no-wait"]) == qore_scan.EXIT_PASS
    assert seen["api_url"] == "https://api.be4breach.com" == qore_scan.DEFAULT_API_URL


def test_an_empty_api_url_variable_still_means_the_default(monkeypatch):
    # a workflow that passes an unset secret gives an empty string, not a missing variable
    monkeypatch.setenv("QORE_API_KEY", KEY)
    monkeypatch.setenv("QORE_API_URL", "   ")
    seen = _capture_start(monkeypatch)
    assert qore_scan.main(["--repo", "acme/api", "--no-wait"]) == qore_scan.EXIT_PASS
    assert seen["api_url"] == qore_scan.DEFAULT_API_URL


def test_a_self_hosted_address_overrides_the_default_by_variable_or_flag(monkeypatch):
    monkeypatch.setenv("QORE_API_KEY", KEY)
    seen = _capture_start(monkeypatch)
    monkeypatch.setenv("QORE_API_URL", "https://qore.corp.example/")
    qore_scan.main(["--repo", "acme/api", "--no-wait"])
    assert seen["api_url"] == "https://qore.corp.example"
    qore_scan.main(["--repo", "acme/api", "--no-wait", "--api-url", "https://other.example"])
    assert seen["api_url"] == "https://other.example"


def test_there_is_no_connector_option_any_more(monkeypatch):
    monkeypatch.setenv("QORE_API_KEY", KEY)
    with pytest.raises(SystemExit):
        qore_scan.parse_args(["--repo", "acme/api", "--connector-id", "x"])
