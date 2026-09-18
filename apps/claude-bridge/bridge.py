#!/usr/bin/env python3
"""Alertmanager -> Claude Code advisory bridge."""

import hashlib
import json
import logging
import os
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("claude-bridge")

VAULT_ADDR = os.environ.get("VAULT_ADDR", "https://vault.vault.svc:8200")
VAULT_ROLE = os.environ.get("VAULT_ROLE", "claude-bridge")
VAULT_MOUNT = os.environ.get("VAULT_MOUNT", "secret")
VAULT_OAUTH_PATH = os.environ.get("VAULT_OAUTH_PATH", "claude-bridge/oauth")
VAULT_SLACK_PATH = os.environ.get("VAULT_SLACK_PATH", "claude-bridge/slack")
VAULT_CACERT = os.environ.get("VAULT_CACERT", "/var/run/vault-ca/ca.crt")
SA_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"

CLAUDE_HOME = os.environ.get("CLAUDE_HOME", "/var/run/claude")
CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "/opt/bin/claude")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-opus-5")
CLAUDE_EFFORT = os.environ.get("CLAUDE_EFFORT", "medium")
RUN_TIMEOUT = int(os.environ.get("RUN_TIMEOUT_SECONDS", "600"))

ALLOWLIST = {a.strip() for a in os.environ.get("ALERT_ALLOWLIST", "").split(",") if a.strip()}
COOLDOWN = int(os.environ.get("COOLDOWN_SECONDS", "3600"))
MAX_RUNS_PER_HOUR = int(os.environ.get("MAX_RUNS_PER_HOUR", "4"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

ALLOWED_TOOLS = [
    "Bash(kubectl get:*)",
    "Bash(kubectl describe:*)",
    "Bash(kubectl logs:*)",
    "Bash(kubectl top:*)",
    "Bash(kubectl events:*)",
    "Bash(kubectl auth can-i:*)",
    "Bash(kubectl api-resources:*)",
    "Bash(kubectl explain:*)",
]
DISALLOWED_TOOLS = ["Read", "Grep", "Glob", "Write", "Edit", "NotebookEdit",
                    "WebFetch", "WebSearch", "Task"]

SYSTEM_PROMPT = """You are an SRE assistant triaging a single Prometheus alert on a
Kubernetes platform cluster named "core". You have READ-ONLY access: your
credentials cannot mutate anything, and write tools are disabled.

Produce a short advisory for a human operator, in this shape:
  WHAT IS WRONG - one or two sentences, concrete.
  EVIDENCE - the specific commands you ran and what they showed.
  LIKELY CAUSE - your best single hypothesis, and how confident you are.
  SUGGESTED ACTION - what a human should do next. If it needs a change, give
  the exact command or manifest edit but state plainly that you did not apply it.

Rules: investigate before concluding. If the evidence is inconclusive, say so
rather than guessing. Never claim to have fixed anything. Do not print secret
values even if you can read them. Keep the whole advisory under 250 words.

Your kubectl credentials are read-only: get, list and watch on workload and
node resources, with no access to secrets. Mutating verbs will be refused by
the API server, so do not attempt them."""


class Gate:

    def __init__(self):
        self._lock = threading.Lock()
        self._last_run = {}
        self._recent = []

    def check(self, alertname, fingerprint):
        if ALLOWLIST and alertname not in ALLOWLIST:
            return False, f"alertname {alertname!r} not in allowlist"
        now = time.time()
        with self._lock:
            self._recent = [t for t in self._recent if now - t < 3600]
            if len(self._recent) >= MAX_RUNS_PER_HOUR:
                return False, f"hourly cap reached ({MAX_RUNS_PER_HOUR}/h)"
            last = self._last_run.get(fingerprint)
            if last is not None and now - last < COOLDOWN:
                return False, f"cooldown, {int(COOLDOWN - (now - last))}s remaining"
            self._last_run[fingerprint] = now
            self._recent.append(now)
        return True, "accepted"


class Vault:
    def __init__(self):
        self._ctx = ssl.create_default_context(cafile=VAULT_CACERT)
        self._token = None

    def _call(self, method, path, body=None, token=None):
        url = f"{VAULT_ADDR}/v1/{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        with urllib.request.urlopen(req, timeout=20, context=self._ctx) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    def login(self):
        with open(SA_TOKEN_FILE) as f:
            jwt = f.read().strip()
        out = self._call("POST", "auth/kubernetes/login", {"role": VAULT_ROLE, "jwt": jwt})
        self._token = out["auth"]["client_token"]
        LOG.info("vault: authenticated via kubernetes auth as role %s", VAULT_ROLE)
        return self._token

    def _authenticated(self, method, path, body=None):
        if not self._token:
            self.login()
        try:
            return self._call(method, path, body, token=self._token)
        except urllib.error.HTTPError as exc:
            if exc.code not in (401, 403):
                raise
            LOG.info("vault: token rejected (%s), re-authenticating", exc.code)
            self.login()
            return self._call(method, path, body, token=self._token)

    def read(self, path):
        out = self._authenticated("GET", f"{VAULT_MOUNT}/data/{path}")
        return out["data"]["data"]

    def write(self, path, data):
        self._authenticated("POST", f"{VAULT_MOUNT}/data/{path}", {"data": data})


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def credentials_path():
    return os.path.join(CLAUDE_HOME, ".claude", ".credentials.json")


def materialise_credentials(vault):
    creds = vault.read(VAULT_OAUTH_PATH)
    target = credentials_path()
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        json.dump(creds, f)
    os.chmod(target, 0o600)
    return digest(creds)


def persist_refreshed_credentials(vault, target, before):
    try:
        with open(target) as f:
            current = json.load(f)
    except (OSError, ValueError) as exc:
        LOG.warning("could not re-read credentials after run: %s", exc)
        return
    if digest(current) == before:
        return
    vault.write(VAULT_OAUTH_PATH, current)
    LOG.info("vault: wrote back refreshed credentials")


def build_prompt(alert):
    labels = alert.get("labels", {})
    anns = alert.get("annotations", {})
    lines = [
        "Triage this firing Prometheus alert on the core cluster.",
        "",
        f"alertname: {labels.get('alertname')}",
        f"severity:  {labels.get('severity')}",
        f"namespace: {labels.get('namespace', '-')}",
        f"summary:     {anns.get('summary', '-')}",
        f"description: {anns.get('description', '-')}",
        "",
        "Other labels: " + json.dumps({k: v for k, v in labels.items()
                                       if k not in ("alertname", "severity", "namespace")}),
        "",
        "Investigate with read-only kubectl, then give the advisory.",
    ]
    return "\n".join(lines)


def terminate_group(proc):
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        proc.kill()
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except OSError:
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def run_claude(prompt):
    cmd = [
        CLAUDE_BIN, "-p", prompt,
        "--output-format", "json",
        "--model", CLAUDE_MODEL,
        "--effort", CLAUDE_EFFORT,
        "--permission-mode", "default",
        "--append-system-prompt", SYSTEM_PROMPT,
        "--strict-mcp-config",
        "--setting-sources", "",
        "--allowedTools", *ALLOWED_TOOLS,
        "--disallowedTools", *DISALLOWED_TOOLS,
    ]
    env = dict(os.environ)
    env["HOME"] = CLAUDE_HOME
    env["PATH"] = "/opt/bin:" + env.get("PATH", "")
    LOG.info("running claude (timeout %ss, model %s)", RUN_TIMEOUT, CLAUDE_MODEL)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env, cwd=CLAUDE_HOME,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        terminate_group(proc)
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            LOG.error("teardown: stdio still held after SIGKILL, abandoning the pipes")
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except OSError:
                    pass
            proc.poll()
        return None, f"claude exceeded the {RUN_TIMEOUT}s wall-clock timeout"
    payload = None
    try:
        payload = json.loads(stdout)
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        denials = payload.get("permission_denials") or []
        if denials:
            blocked = []
            for d in denials:
                if not isinstance(d, dict):
                    continue
                tool_input = d.get("tool_input")
                command = tool_input.get("command") if isinstance(tool_input, dict) else None
                blocked.append(command or d.get("tool_name") or "?")
            LOG.warning("%d tool call(s) denied by the permission layer: %s",
                        len(denials), "; ".join(str(x)[:120] for x in blocked[:5]))

    if isinstance(payload, dict) and payload.get("is_error"):
        reason = payload.get("terminal_reason") or "unknown"
        return None, f"claude reported an error ({reason}): {str(payload.get('result'))[:400]}"
    if proc.returncode != 0:
        detail = stderr.strip()
        if isinstance(payload, dict) and payload.get("result"):
            detail = f"{payload['result']} (terminal_reason={payload.get('terminal_reason')})"
        return None, f"claude exited {proc.returncode}: {detail[:500]}"
    if payload is None:
        return stdout.strip(), None
    if isinstance(payload, dict):
        return payload.get("result") or json.dumps(payload)[:2000], None
    return json.dumps(payload)[:2000], None


def post_slack(webhook, alertname, body, failed=False):
    icon = ":warning:" if failed else ":mag:"
    title = f"{icon} Claude advisory — {alertname}"
    payload = {
        "text": title,
        "blocks": [
            {"type": "section",
             "text": {"type": "mrkdwn", "text": f"*{title}*"}},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": f"```{body[:2800]}```"}},
            {"type": "context",
             "elements": [{"type": "mrkdwn",
                           "text": "advisory only — read-only access, nothing was changed"}]},
        ],
    }
    req = urllib.request.Request(webhook, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
    except urllib.error.URLError as exc:
        LOG.error("slack post failed: %s", exc)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def do_GET(self):
        if self.path in ("/healthz", "/readyz"):
            self._reply(200, b"ok")
        else:
            self._reply(404, b"not found")

    def do_POST(self):
        if self.path != "/alert":
            self._reply(404, b"not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._reply(400, b"invalid json")
            return
        self._reply(202, b"accepted")
        threading.Thread(target=self.server.dispatch, args=(payload,), daemon=True).start()


class Bridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, vault, gate):
        super().__init__(addr, Handler)
        self.vault = vault
        self.gate = gate
        self._run_lock = threading.Lock()

    def dispatch(self, payload):
        for alert in payload.get("alerts", []):
            if alert.get("status") != "firing":
                continue
            labels = alert.get("labels", {})
            name = labels.get("alertname", "unknown")
            fp = alert.get("fingerprint") or digest(labels)
            ok, why = self.gate.check(name, fp)
            if not ok:
                LOG.info("skipping %s (%s): %s", name, fp[:8], why)
                continue
            with self._run_lock:
                try:
                    self.handle_alert(alert, name)
                except Exception:  # noqa: BLE001
                    LOG.exception("unhandled error while triaging %s (%s)", name, fp[:8])

    def handle_alert(self, alert, name):
        LOG.info("triaging %s", name)
        try:
            slack = self.vault.read(VAULT_SLACK_PATH).get("webhook_url")
        except Exception as exc:  # noqa: BLE001
            LOG.error("vault read failed for %s (%s): %s", name, VAULT_SLACK_PATH, exc)
            return
        try:
            before = materialise_credentials(self.vault)
        except Exception as exc:  # noqa: BLE001
            LOG.error("credential setup failed for %s: %s", name, exc)
            return
        if DRY_RUN:
            LOG.info("DRY_RUN set; would have triaged %s", name)
            return
        try:
            body, err = run_claude(build_prompt(alert))
            persist_refreshed_credentials(self.vault, credentials_path(), before)
        finally:
            shutil.rmtree(os.path.join(CLAUDE_HOME, ".claude", "projects"), ignore_errors=True)
        if err:
            LOG.error("run failed for %s: %s", name, err)
            if slack:
                post_slack(slack, name, err, failed=True)
            return
        LOG.info("advisory for %s: %s", name, body.replace("\n", " ")[:400])
        if slack:
            post_slack(slack, name, body)


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if not os.path.exists(CLAUDE_BIN):
        LOG.error("claude binary missing at %s", CLAUDE_BIN)
        return 1
    if not os.path.exists(VAULT_CACERT):
        LOG.error("vault CA bundle missing at %s", VAULT_CACERT)
        return 1
    vault = Vault()
    vault.login()
    server = Bridge(("", 8080), vault, Gate())
    LOG.info("listening on :8080  allowlist=%s cooldown=%ss cap=%s/h dry_run=%s",
             sorted(ALLOWLIST) or "<any>", COOLDOWN, MAX_RUNS_PER_HOUR, DRY_RUN)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
