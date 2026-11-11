"""Capture M08 GitHub API values and raw logs; credentials stay in memory only.

Run explicitly after publication. Authenticated requests never follow redirects.
The short-lived log-storage redirect receives no Authorization and is never
printed, forwarded to a tool, or written into any retained receipt.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from freeze_m08_publication import ROOT, WORK, REPOSITORY, check_run, hex_value, require, save, sha

BASE = "https://api.github.com/repos/" + REPOSITORY
USER_AGENT = "NIST-M08-publication-maintenance"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, response_headers, new_url):
        return None


def authentication():
    environment = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GCM_GUI_PROMPT="0")
    process = subprocess.run(["git", "-C", str(ROOT / "publication/majax_mlkem1536"), "credential", "fill"],
                             input="protocol=https\nhost=github.com\n\n", capture_output=True, text=True,
                             env=environment, timeout=15)
    require(process.returncode == 0, "GitHub credential unavailable; no credential output is retained")
    fields = dict(line.split("=", 1) for line in process.stdout.splitlines() if "=" in line)
    require(fields.get("password"), "GitHub credential password unavailable")
    return {"Authorization": "Bearer " + fields["password"], "Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}


def read_api(endpoint, headers):
    # Refuse any redirect of an authenticated API request.
    request = urllib.request.Request(BASE + endpoint, headers=headers)
    with urllib.request.build_opener(NoRedirect).open(request, timeout=40) as response:
        return json.load(response)


def download_logs(run_id, headers, destination):
    request = urllib.request.Request(BASE + f"/actions/runs/{run_id}/logs", headers=headers)
    try:
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=40)
        except urllib.error.HTTPError as error:
            if error.code != 302:
                raise
            location = error.headers.get("Location", "")
            parsed = urllib.parse.urlsplit(location)
            require(parsed.scheme == "https" and parsed.hostname and parsed.username is None and parsed.password is None,
                    "unexpected log-storage redirect")
            # No Authorization is supplied to storage. Do not log this URL.
            response = urllib.request.urlopen(urllib.request.Request(location, headers={"User-Agent": USER_AGENT}), timeout=40)
        total = 0
        with response, destination.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                require(total <= 512 * 1024 * 1024, "compressed CI logs exceed capture budget")
                output.write(chunk)
    except Exception:
        # HTTP/network exception text can include the signed storage URL.
        raise ValueError("CI log download failed; partial evidence is preserved and private URL details are suppressed") from None


def capture(run_id, public_commit, branch="main", status_only=False):
    require(type(run_id) is int and run_id > 0 and hex_value(public_commit, 40) and branch == "main",
            "explicit positive run, full public commit and main branch required")
    headers = authentication()
    run = read_api(f"/actions/runs/{run_id}", headers)
    jobs = read_api(f"/actions/runs/{run_id}/jobs?per_page=100", headers)
    check_run(run, jobs, run_id, public_commit, branch, successful=not status_only)
    summary = {"run_id": run_id, "public_commit": public_commit, "status": run["status"], "conclusion": run["conclusion"],
               "jobs": [{key: job[key] for key in ("id", "name", "status", "conclusion")} for job in jobs["jobs"]]}
    if status_only:
        return summary
    destination = WORK / str(run_id)
    require(destination.resolve().parent == WORK.resolve() and not destination.exists(), "new per-run M08 capture directory required")
    destination.mkdir(parents=True)
    download_logs(run_id, headers, destination / "ci-logs.zip")
    for name, data in (("run.json", run), ("jobs.json", jobs)):
        save(destination / name, data)
    save(destination / "receipt.json", {"schema": "m08-ci-capture-v1", "scope": "Parsed API run/jobs reserialized as JSON, plus raw hosted full log archive",
        "run_id": run_id, "public_commit": public_commit, "run_url": run["html_url"],
        "sha256": {name: sha(destination / name) for name in ("run.json", "jobs.json", "ci-logs.zip")},
        "credentials_retained": False, "signed_log_storage_URL_retained": False})
    return {**summary, "destination": str(destination), "captured_members": 3,
            "scope": "Capture only; freeze validates full job test counts, native M08 output and committed source integrity"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", type=int)
    parser.add_argument("--public-commit", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--status-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(capture(args.run_id, args.public_commit, args.branch, args.status_only), indent=2))


if __name__ == "__main__":
    main()
