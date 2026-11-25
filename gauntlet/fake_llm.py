"""A scripted, deterministic OpenAI-compatible model endpoint.

The gauntlet tests the host's enforcement code, not a model's judgement, so
the "model" is a script: each agent turn pops the next scripted step (a set of
tool calls or a final text). Tool names in the script are regular expressions
matched against the tool names the host actually advertised in that request,
so a scenario does not need to know each host's prefixing convention.

Every request the host sends is logged (FAKE_LLM_LOG), which gives a second
oracle: exactly what the host showed the model (tool descriptions, tool
results, system prompt), byte for byte.

Requests are classified:
  agent      the request advertises at least one tool from the scenario's
             hostile servers (or the scenario says match_any)
  auxiliary  anything else (session titles, permission judges, summaries);
             answered with the scenario's aux_reply (default "ok")
"""

import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Track:
    def __init__(self, spec):
        self.turns = list(spec.get("turns", []))
        self.agent_marker = spec.get("agent_marker")
        self.position = 0

    def matches(self, names):
        if not names:
            return False
        if not self.agent_marker:
            return True
        return any(re.search(self.agent_marker, n) for n in names)


class Script:
    """One or more tracks. A request belongs to the first track whose marker
    matches one of the advertised tool names; that lets one scripted model
    serve several concurrent sessions deterministically."""

    def __init__(self, script):
        specs = script.get("tracks") or [script]
        self.tracks = [Track(s) for s in specs]
        self.aux_reply = script.get("aux_reply", "ok")
        self.aux_rules = script.get("aux_rules", [])
        self.lock = threading.Lock()

    def track_for(self, body):
        names = [tool_name(t) for t in body.get("tools") or []]
        for track in self.tracks:
            if track.matches(names):
                return track
        return None

    def is_agent_request(self, body):
        return self.track_for(body) is not None

    def aux_answer(self, body):
        text = json.dumps(body.get("messages", []), ensure_ascii=False)
        for rule in self.aux_rules:
            if re.search(rule["match"], text, re.S):
                return rule["reply"]
        return self.aux_reply

    def next_turn(self, body):
        track = self.track_for(body)
        with self.lock:
            if track.position < len(track.turns):
                turn = track.turns[track.position]
                track.position += 1
                return turn
            return {"text": "done"}


def tool_name(tool):
    if "function" in tool:
        return tool["function"].get("name", "")
    return tool.get("name", "")


def resolve_calls(turn, advertised):
    calls = []
    for i, call in enumerate(turn.get("tool_calls", [])):
        pattern = call["tool"]
        if call.get("literal"):
            name = pattern
        else:
            matches = [n for n in advertised if re.fullmatch(pattern, n)]
            if not matches:
                matches = [n for n in advertised if re.search(pattern, n)]
            name = matches[0] if matches else pattern
        calls.append({
            "id": f"call_{int(time.time() * 1000) % 10**9}_{i}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(call.get("arguments", {}))},
        })
    return calls


def normalize_anthropic(body):
    """Rewrite an Anthropic Messages request into the OpenAI chat shape so
    every oracle reads one format, whichever provider path the host used."""
    messages = []
    system = body.get("system")
    if system:
        text = system if isinstance(system, str) else "".join(b.get("text", "") for b in system)
        messages.append({"role": "system", "content": text})
    for m in body.get("messages", []):
        content = m.get("content")
        if isinstance(content, str):
            messages.append({"role": m["role"], "content": content})
            continue
        other = []
        for block in content or []:
            if block.get("type") == "tool_result":
                messages.append({"role": "tool", "tool_call_id": block.get("tool_use_id"),
                                 "content": block.get("content")})
            else:
                other.append(block)
        if other:
            messages.append({"role": m["role"], "content": other})
    tools = [{"type": "function", "function": {"name": t.get("name"), "description": t.get("description"),
                                               "parameters": t.get("input_schema")}}
             for t in body.get("tools") or []]
    return {"model": body.get("model"), "messages": messages, "tools": tools, "_format": "anthropic"}


class FakeLLM:
    def __init__(self, script, log_path=None):
        self.script = Script(script)
        self.log_path = log_path
        self.log_lock = threading.Lock()

    def log(self, rec):
        if not self.log_path:
            return
        rec = dict(rec, t=time.time())
        with self.log_lock, open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def respond(self, body, raw=None):
        advertised = [tool_name(t) for t in body.get("tools") or []]
        if self.script.is_agent_request(body):
            turn = self.script.next_turn(body)
            if turn.get("delay_seconds"):
                time.sleep(turn["delay_seconds"])
            calls = resolve_calls(turn, advertised)
            kind = "agent"
            message = {"role": "assistant", "content": turn.get("text") if not calls else None}
            if calls:
                message["tool_calls"] = calls
        else:
            kind = "auxiliary"
            message = {"role": "assistant", "content": self.script.aux_answer(body)}
            calls = []
        self.log({"kind": kind, "request": body, "reply": message,
                  **({"raw_request": raw} if raw is not None else {})})
        return message, ("tool_calls" if calls else "stop")


def make_handler(llm):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def send_json(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.rstrip("/").endswith("/models"):
                self.send_json(200, {"object": "list", "data": [
                    {"id": "gauntlet-model", "object": "model", "owned_by": "gauntlet"}]})
            else:
                self.send_json(404, {"error": {"message": "not found"}})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self.send_json(400, {"error": {"message": "bad json"}})
                return
            if self.path.rstrip("/").endswith("/messages"):
                self.anthropic(body)
                return
            if not self.path.rstrip("/").endswith("chat/completions"):
                llm.log({"kind": "unsupported_path", "path": self.path, "request": body})
                self.send_json(404, {"error": {"message": f"unsupported path {self.path}"}})
                return
            message, finish = llm.respond(body)
            created = int(time.time())
            usage = {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
            if body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                delta = {"role": "assistant"}
                if message.get("content"):
                    delta["content"] = message["content"]
                if message.get("tool_calls"):
                    delta["tool_calls"] = [dict(c, index=i) for i, c in enumerate(message["tool_calls"])]
                chunks = [
                    {"id": "chatcmpl-g", "object": "chat.completion.chunk", "created": created,
                     "model": "gauntlet-model",
                     "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                    {"id": "chatcmpl-g", "object": "chat.completion.chunk", "created": created,
                     "model": "gauntlet-model",
                     "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                     "usage": usage},
                ]
                for chunk in chunks:
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
                self.close_connection = True
            else:
                self.send_json(200, {
                    "id": "chatcmpl-g", "object": "chat.completion", "created": created,
                    "model": "gauntlet-model",
                    "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                    "usage": usage,
                })

        def anthropic(self, body):
            message, finish = llm.respond(normalize_anthropic(body), raw=body)
            blocks = []
            if message.get("content"):
                blocks.append({"type": "text", "text": message["content"]})
            for c in message.get("tool_calls") or []:
                blocks.append({"type": "tool_use", "id": "toolu_" + c["id"], "name": c["function"]["name"],
                               "input": json.loads(c["function"]["arguments"])})
                c["id"] = "toolu_" + c["id"]
            stop = "tool_use" if finish == "tool_calls" else "end_turn"
            usage = {"input_tokens": 10, "output_tokens": 10}
            msg = {"id": "msg_g", "type": "message", "role": "assistant", "model": body.get("model"),
                   "content": blocks, "stop_reason": stop, "stop_sequence": None, "usage": usage}
            if not body.get("stream"):
                self.send_json(200, msg)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()

            def ev(name, data):
                self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())

            ev("message_start", {"type": "message_start", "message": dict(msg, content=[], stop_reason=None)})
            for i, b in enumerate(blocks):
                if b["type"] == "text":
                    ev("content_block_start", {"type": "content_block_start", "index": i,
                                               "content_block": {"type": "text", "text": ""}})
                    ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                               "delta": {"type": "text_delta", "text": b["text"]}})
                else:
                    ev("content_block_start", {"type": "content_block_start", "index": i,
                                               "content_block": {"type": "tool_use", "id": b["id"],
                                                                 "name": b["name"], "input": {}}})
                    ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                               "delta": {"type": "input_json_delta",
                                                         "partial_json": json.dumps(b["input"])}})
                ev("content_block_stop", {"type": "content_block_stop", "index": i})
            ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                 "usage": {"output_tokens": 10}})
            ev("message_stop", {"type": "message_stop"})
            self.wfile.flush()
            self.close_connection = True

    return Handler


def serve(script, log_path=None, port=0):
    llm = FakeLLM(script, log_path)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(llm))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, llm


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        script = json.load(f)
    srv, _ = serve(script, sys.argv[2] if len(sys.argv) > 2 else None,
                   int(sys.argv[3]) if len(sys.argv) > 3 else 8765)
    print(f"listening on {srv.server_address}", flush=True)
    threading.Event().wait()
