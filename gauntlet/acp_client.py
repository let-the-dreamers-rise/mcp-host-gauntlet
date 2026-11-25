"""Minimal Agent Client Protocol (ACP) client used to drive an agent host.

The client plays the human: it opens a session with the scenario's hostile MCP
servers attached, sends one prompt, and answers every permission request with
the scenario's policy (for example: reject everything, or allow_always the
first time). Every message in both directions is recorded, so a verdict can
say exactly which tool calls the host asked about.
"""

import json
import queue
import subprocess
import threading
import time


class ACPError(Exception):
    pass


class ACPClient:
    def __init__(self, argv, env, cwd, permission_policy, transcript, stderr_path=None):
        self.transcript = transcript
        self.permission_policy = permission_policy
        self.permission_requests = []
        self.updates = []
        self.next_id = 1
        self.write_lock = threading.Lock()
        self.id_lock = threading.Lock()
        self.responses = {}
        self.cond = threading.Condition()
        self.closed = False
        self.stderr_file = open(stderr_path, "w") if stderr_path else subprocess.DEVNULL
        self.proc = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr_file, text=True, encoding="utf-8", bufsize=1)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def record(self, direction, msg):
        self.transcript.append({"t": time.time(), "dir": direction, "msg": msg})

    def _write(self, msg):
        with self.write_lock:
            self.record("out", msg)
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()

    def _read(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.record("in-garbage", line[:2000])
                continue
            self.record("in", msg)
            if "method" in msg and "id" in msg:
                self._on_request(msg)
            elif "method" in msg:
                if msg["method"] == "session/update":
                    self.updates.append(msg.get("params"))
            else:
                with self.cond:
                    self.responses[msg.get("id")] = msg
                    self.cond.notify_all()
        with self.cond:
            self.closed = True
            self.cond.notify_all()

    def _on_request(self, msg):
        method = msg["method"]
        if method == "session/request_permission":
            params = msg.get("params", {})
            index = len(self.permission_requests)
            option = self.permission_policy(index, params)
            self.permission_requests.append({"params": params, "answer": option})
            if option is None:
                outcome = {"outcome": "cancelled"}
            else:
                outcome = {"outcome": "selected", "optionId": option}
            self._write({"jsonrpc": "2.0", "id": msg["id"], "result": {"outcome": outcome}})
        else:
            self._write({"jsonrpc": "2.0", "id": msg["id"],
                         "error": {"code": -32601, "message": f"client does not support {method}"}})

    def request(self, method, params, timeout=60):
        with self.id_lock:
            rid = self.next_id
            self.next_id += 1
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + timeout
        with self.cond:
            while rid not in self.responses:
                remaining = deadline - time.time()
                if remaining <= 0 or self.closed:
                    raise ACPError(f"{method}: no response ({'closed' if self.closed else 'timeout'})")
                self.cond.wait(remaining)
            msg = self.responses.pop(rid)
        if "error" in msg:
            raise ACPError(f"{method}: {msg['error']}")
        return msg.get("result")

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        if self.stderr_file not in (None, subprocess.DEVNULL):
            self.stderr_file.close()


def policy_from_spec(spec):
    """spec: a single option id for every request, or a list consumed in order
    (the last entry repeats). Option ids are matched against the options the
    host offered by kind first, then by id."""
    import re

    if isinstance(spec, dict):
        rules = [(re.compile(k), v if isinstance(v, list) else [v])
                 for k, v in spec.get("by_tool", {}).items()]
        default = spec.get("default", "reject_once")
        default = default if isinstance(default, list) else [default]
    else:
        rules = []
        default = spec if isinstance(spec, list) else [spec]
    seen = {}

    def choose(index, params):
        title = json.dumps(params.get("toolCall", {}), ensure_ascii=False)
        answers = default
        key = "__default__"
        for pattern, rule_answers in rules:
            if pattern.search(title):
                answers, key = rule_answers, pattern.pattern
                break
        n = seen.get(key, 0)
        seen[key] = n + 1
        wanted = answers[min(n, len(answers) - 1)]
        if wanted in (None, "cancel"):
            return None
        for option in params.get("options", []):
            if option.get("kind") == wanted or option.get("optionId") == wanted:
                return option["optionId"]
        return wanted

    return choose
