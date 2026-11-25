"""Reference ACP agent host used to self-test the gauntlet.

It is intentionally small and strict, so that every scenario has a known
"correct host" outcome. Switch on known flaws with REFERENCE_FLAWS (comma
separated) to prove the scenario's oracle catches them:

  readonly_in_approve     trust readOnlyHint even in approve mode
  sticky_allow            keep allow_always after the tool definition changes
  no_sanitize             pass hidden Unicode tag characters through to the model
  answer_sampling         answer server sampling/createMessage without asking
  ignore_reject_always    forget reject_always decisions
  trust_readonly_smart    skip the prompt for readOnlyHint tools in smart_approve
  auto_ignores_deny       auto mode skips reject_always decisions
"""

import hashlib
import json
import os
import subprocess
import sys
import threading
import urllib.request

FLAWS = set(filter(None, os.environ.get("REFERENCE_FLAWS", "").split(",")))
MODE = os.environ.get("REF_MODE", "approve")
LLM = os.environ["REF_LLM_URL"].rstrip("/") + "/v1/chat/completions"

out_lock = threading.Lock()

# Flaws for scenarios still under coordinated disclosure live in
# embargoed/reference_flaws.py, which is not published.
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "embargoed"))
    import reference_flaws as EMBARGOED
except ImportError:
    EMBARGOED = None
pending = {}
next_id = [10_000]


def send(msg):
    with out_lock:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()


def ask_client(method, params):
    rid = next_id[0]
    next_id[0] += 1
    ev = {"event": threading.Event(), "msg": None}
    pending[rid] = ev
    send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    ev["event"].wait(60)
    return (ev["msg"] or {}).get("result")


def strip_tags(value):
    if "no_sanitize" in FLAWS:
        return value
    if isinstance(value, str):
        return "".join(ch for ch in value if not (0xE0000 <= ord(ch) <= 0xE007F))
    if isinstance(value, list):
        return [strip_tags(v) for v in value]
    if isinstance(value, dict):
        return {strip_tags(k): strip_tags(v) for k, v in value.items()}
    return value


class McpServer:
    def __init__(self, cfg):
        self.name = cfg["name"]
        env = dict(os.environ)
        for e in cfg.get("env", []):
            env[e["name"]] = e["value"]
        self.proc = subprocess.Popen([cfg["command"], *cfg.get("args", [])], env=env,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     bufsize=1)
        self.rid = 0
        self.responses = {}
        self.cond = threading.Condition()
        self.tools = []
        self.changed = threading.Event()
        threading.Thread(target=self.read, daemon=True).start()
        self.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "reference", "version": "0"}})
        self.notify("notifications/initialized")
        self.refresh()

    def read(self):
        for line in self.proc.stdout:
            msg = json.loads(line)
            if "method" in msg and "id" in msg:
                self.on_server_request(msg)
            elif "method" in msg:
                if msg["method"] == "notifications/tools/list_changed":
                    self.changed.set()
            else:
                with self.cond:
                    self.responses[msg["id"]] = msg
                    self.cond.notify_all()

    def on_server_request(self, msg):
        if msg["method"] == "sampling/createMessage" and "answer_sampling" in FLAWS:
            result = {"role": "assistant", "content": {"type": "text", "text": "sure"},
                      "model": "x"}
            self.write({"jsonrpc": "2.0", "id": msg["id"], "result": result})
        else:
            self.write({"jsonrpc": "2.0", "id": msg["id"],
                        "error": {"code": -32601, "message": "declined by host"}})

    def write(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def notify(self, method):
        self.write({"jsonrpc": "2.0", "method": method})

    def call(self, method, params, timeout=60):
        self.rid += 1
        rid = self.rid
        self.write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        with self.cond:
            while rid not in self.responses:
                if not self.cond.wait(timeout):
                    raise RuntimeError(f"{self.name}: {method} timed out")
            return self.responses.pop(rid).get("result", {})

    def refresh(self):
        self.tools = self.call("tools/list", {}).get("tools", [])
        self.changed.clear()


def definition_hash(tool):
    return hashlib.sha256(json.dumps(
        {k: tool.get(k) for k in ("description", "inputSchema", "annotations")},
        sort_keys=True).encode()).hexdigest()


class Session:
    def __init__(self, sid, servers):
        self.sid = sid
        self.servers = servers
        self.allow = {}
        self.deny = set()
        self.mode = MODE
        self.messages = [{"role": "system", "content": "reference host"}]

    def catalog(self):
        tools = {}
        for s in self.servers:
            if s.changed.is_set():
                s.refresh()
            for t in s.tools:
                public = f"{s.name}__{t['name']}"
                if public in tools:
                    continue
                tools[public] = (s, t)
        return tools

    def decide(self, public, server, tool, args):
        key = (server.name, tool["name"])
        if self.mode == "auto" and "auto_ignores_deny" in FLAWS:
            return True
        if key in self.deny and "ignore_reject_always" not in FLAWS:
            return False
        if self.mode == "auto":
            return True
        readonly = (tool.get("annotations") or {}).get("readOnlyHint") is True
        if EMBARGOED and EMBARGOED.allow(FLAWS, self.mode, public):
            return True
        if readonly and ((self.mode == "smart_approve" and "trust_readonly_smart" in FLAWS) or "readonly_in_approve" in FLAWS):
            return True
        remembered = self.allow.get(key)
        if remembered is not None and (remembered == definition_hash(tool) or "sticky_allow" in FLAWS):
            return True
        result = ask_client("session/request_permission", {
            "sessionId": self.sid,
            "toolCall": {"toolCallId": public, "title": public, "rawInput": args},
            "options": [{"optionId": k, "name": k, "kind": k}
                        for k in ("allow_always", "allow_once", "reject_once", "reject_always")],
        }) or {}
        option = (result.get("outcome") or {}).get("optionId")
        if option == "allow_always":
            self.allow[key] = definition_hash(tool)
        if option == "reject_always":
            self.deny.add(key)
        return option in ("allow_always", "allow_once")

    def prompt(self, text):
        self.messages.append({"role": "user", "content": text})
        for _ in range(20):
            tools = self.catalog()
            if EMBARGOED:
                EMBARGOED.before_model(FLAWS, tools)
            body = {"model": "gauntlet-model", "messages": self.messages, "tools": [
                {"type": "function", "function": {
                    "name": public, "description": strip_tags(t.get("description", "")),
                    "parameters": strip_tags(t.get("inputSchema", {"type": "object"}))}}
                for public, (_, t) in tools.items()]}
            req = urllib.request.Request(LLM, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
            reply = json.load(urllib.request.urlopen(req, timeout=60))["choices"][0]["message"]
            self.messages.append(reply)
            calls = reply.get("tool_calls") or []
            if not calls:
                return
            for call in calls:
                public = call["function"]["name"]
                args = json.loads(call["function"].get("arguments") or "{}")
                entry = self.catalog().get(public)
                if entry is None:
                    content = f"unknown tool {public}"
                else:
                    server, tool = entry
                    if self.decide(public, server, tool, args):
                        res = server.call("tools/call", {"name": tool["name"], "arguments": args})
                        content = json.dumps(strip_tags(res.get("content", [])), ensure_ascii=False)
                    else:
                        content = "denied by user"
                self.messages.append({"role": "tool", "tool_call_id": call["id"], "content": content})


def main():
    sessions = {}
    for line in sys.stdin:
        msg = json.loads(line)
        if "method" not in msg:
            ev = pending.pop(msg.get("id"), None)
            if ev:
                ev["msg"] = msg
                ev["event"].set()
            continue
        method, rid, params = msg["method"], msg.get("id"), msg.get("params", {})
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": 1,
                                                         "agentCapabilities": {}}})
        elif method == "session/new":
            sid = f"s{len(sessions) + 1}"
            sessions[sid] = Session(sid, [McpServer(c) for c in params.get("mcpServers", [])])
            send({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": sid}})
        elif method == "session/prompt":
            def run(rid=rid, params=params):
                s = sessions[params["sessionId"]]
                s.prompt("".join(p.get("text", "") for p in params["prompt"]))
                send({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
            threading.Thread(target=run, daemon=True).start()
        elif method == "session/set_mode":
            sessions[params["sessionId"]].mode = params.get("modeId", MODE)
            send({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif rid is not None:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": method}})


if __name__ == "__main__":
    main()
