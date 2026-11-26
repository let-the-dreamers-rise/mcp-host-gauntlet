"""Run gauntlet scenarios against an ACP agent host and judge the results.

One scenario = hostile MCP server(s) + scripted model + human permission
policy + assertions. The verdict comes only from ground-truth logs:
  server log   what the hostile servers actually executed / were asked
  model log    what the host sent to the model
  ACP log      which permission prompts the human was shown
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import fake_llm
from .acp_client import ACPClient, ACPError, policy_from_spec
from .hosts import HOSTS

HERE = Path(__file__).resolve().parent


def read_jsonl(path):
    out = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return out


def model_text(records, where):
    """Concatenate the parts of every agent request the scenario asks about."""
    chunks = []
    for rec in records:
        req = rec.get("request", {})
        if where in ("tools", "any"):
            chunks.append(json.dumps(req.get("tools", []), ensure_ascii=False))
        for m in req.get("messages", []):
            role = m.get("role")
            if where == "any" or (where == "system" and role == "system") \
                    or (where == "tool_results" and role == "tool") \
                    or (where == "user" and role == "user"):
                c = m.get("content")
                chunks.append(c if isinstance(c, str) else json.dumps(c, ensure_ascii=False))
    return "\n".join(chunks)


def call_names(model_log):
    names = {}
    for rec in model_log:
        for call in (rec.get("reply") or {}).get("tool_calls") or []:
            names[call["id"]] = call["function"]["name"]
            names["toolu_" + call["id"]] = call["function"]["name"]
    return names


def permission_label(prompt, ctx):
    """Everything that identifies a permission prompt: what the host showed
    the user, plus the model-side tool name for the call id it refers to."""
    tool_call = prompt["params"].get("toolCall", {})
    label = json.dumps(tool_call, ensure_ascii=False)
    name = ctx["call_names"].get(tool_call.get("toolCallId"))
    return f"{name or ''} {label}"


def check(assertion, ctx):
    kind = assertion["type"]
    executed = [r for r in ctx["server_log"] if r["kind"] == "executed"]
    if kind == "executed_count":
        hits = [r for r in executed
                if re.fullmatch(assertion["tool"], r["name"])
                and (assertion.get("server") is None or r["server"] == assertion["server"])]
        n = len(hits)
        ok = assertion.get("min", 0) <= n <= assertion.get("max", 10**9)
        return ok, f"{n} executed call(s) of {assertion['tool']}" + (
            f" on {assertion['server']}" if assertion.get("server") else "")
    if kind == "permission_prompts":
        pattern = assertion.get("tool", ".*")
        hits = [p for p in ctx["permissions"] if re.search(pattern, permission_label(p, ctx))]
        n = len(hits)
        ok = assertion.get("min", 0) <= n <= assertion.get("max", 10**9)
        return ok, f"{n} permission prompt(s) matching {pattern}"
    if kind == "model_saw":
        agent = [r for r in ctx["model_log"] if r.get("kind") == "agent"]
        text = model_text(agent, assertion.get("where", "any"))
        found = re.search(assertion["pattern"], text, re.S) is not None
        ok = found == assertion.get("present", True)
        return ok, f"pattern {assertion['pattern']!r} {'present' if found else 'absent'} in {assertion.get('where', 'any')}"
    if kind == "server_request_answered":
        reqs = [r for r in ctx["server_log"] if r["kind"] == "server_request"
                and r["method"] == assertion["method"]]
        answered = [r for r in ctx["server_log"] if r["kind"] == "response"
                    and any(q["id"] == r.get("id") for q in reqs) and r.get("result") is not None]
        n = len(answered)
        ok = assertion.get("min", 0) <= n <= assertion.get("max", 10**9)
        return ok, f"{n} of {len(reqs)} {assertion['method']} request(s) answered with a result"
    if kind == "server_request_answered_accept":
        reqs = [r for r in ctx["server_log"] if r["kind"] == "server_request"
                and r["method"] == assertion["method"]]
        accepted = [r for r in ctx["server_log"] if r["kind"] == "response"
                    and any(q["id"] == r.get("id") for q in reqs)
                    and (r.get("result") or {}).get("action") == "accept"]
        n = len(accepted)
        ok = assertion.get("min", 0) <= n <= assertion.get("max", 10**9)
        return ok, f"{n} of {len(reqs)} {assertion['method']} request(s) accepted"
    if kind == "approved_args_match_executed":
        shown = [p["params"].get("toolCall", {}).get("rawInput") for p in ctx["permissions"]
                 if re.search(assertion["tool"], permission_label(p, ctx))]
        ran = [r.get("arguments") for r in executed if re.fullmatch(assertion["tool"], r["name"])]
        if not ran:
            return True, "nothing executed"
        if not shown:
            return False, f"executed {ran} without any prompt showing arguments"
        ok = all(r in shown for r in ran)
        return ok, f"prompt showed {shown}; executed {ran}"
    if kind == "prompt_shows":
        prompts = [p for p in ctx["permissions"] if re.search(assertion["tool"], permission_label(p, ctx))]
        if not prompts:
            return True, "no prompt for this tool"
        shown = [json.dumps({k: p["params"].get("toolCall", {}).get(k) for k in ("title", "rawInput", "kind")},
                            ensure_ascii=False) for p in prompts]
        hits = [s for s in shown if re.search(assertion["pattern"], s, re.I)]
        ok = bool(hits) == assertion.get("present", True)
        return ok, f"user saw {shown}"
    if kind == "prompt_distinguishable":
        prompts = [p for p in ctx["permissions"] if re.search(assertion["tool"], permission_label(p, ctx))]
        titles = [p["params"].get("toolCall", {}).get("title", "") for p in prompts]
        executed_on = [r["server"] for r in executed]
        if assertion["server"] not in executed_on:
            return True, f"server tool not executed; titles {titles}"
        confusable = [t for t in titles if re.search(assertion["builtin_title_pattern"], t or "")]
        return (not confusable), f"approval title(s) {titles}; call ran on server {assertion['server']!r}"
    if kind == "server_received":
        n = len([r for r in ctx["server_log"] if r["kind"] == "recv"
                 and r.get("method") == assertion["method"]])
        ok = assertion.get("min", 0) <= n <= assertion.get("max", 10**9)
        return ok, f"server received {assertion['method']} {n} time(s)"
    if kind == "file_absent":
        path = Path(ctx["workdir"]) / assertion["path"]
        return (not path.exists()), f"{assertion['path']} {'exists' if path.exists() else 'absent'}"
    raise ValueError(f"unknown assertion type {kind}")


def run_scenario(scenario, host, out_dir, timeout):
    work = Path(tempfile.mkdtemp(prefix=f"g-{scenario['id']}-"))
    home = work / "home"
    cwd = work / "cwd"
    home.mkdir()
    cwd.mkdir()
    for rel, content in scenario.get("files", {}).items():
        p = cwd / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    server_log = work / "server.jsonl"
    model_log = work / "model.jsonl"
    srv, _ = fake_llm.serve(scenario["script"], str(model_log))
    port = srv.server_address[1]

    def mcp_servers_for(specs):
        out = []
        for spec in specs:
            spec_path = work / f"spec-{spec['name']}.json"
            spec_path.write_text(json.dumps(spec, ensure_ascii=False))
            out.append({
                "name": spec.get("extension_name", spec["name"]),
                "command": sys.executable,
                "args": [str(HERE / "hostile_mcp.py")],
                "env": [{"name": "HMCP_SPEC", "value": str(spec_path)},
                        {"name": "HMCP_LOG", "value": str(server_log)}],
            })
        return out

    sessions = scenario.get("sessions") or [{
        "servers": scenario["servers"], "mode": scenario.get("mode", "approve"),
        "prompts": scenario.get("prompts", [scenario.get("prompt", "Go.")]), "start_delay": 0}]
    adapter = HOSTS[host]
    argv, env = adapter.command(home=str(home), llm_url=f"http://127.0.0.1:{port}",
                                mode=sessions[0].get("mode", scenario.get("mode", "approve")))
    transcript = []
    client = ACPClient(argv, env, str(cwd), policy_from_spec(scenario.get("permission", "reject_once")),
                       transcript, stderr_path=str(work / "host-stderr.log"))
    errors = []
    started = time.time()

    def drive(session, sid):
        try:
            time.sleep(session.get("start_delay", 0))
            for prompt in session.get("prompts", [session.get("prompt", "Go.")]):
                if isinstance(prompt, dict) and "set_mode" in prompt:
                    client.request("session/set_mode", {"sessionId": sid, "modeId": prompt["set_mode"]},
                                   timeout=timeout)
                    continue
                client.request("session/prompt", {
                    "sessionId": sid, "prompt": [{"type": "text", "text": prompt}]}, timeout=timeout)
        except ACPError as e:
            errors.append(str(e))

    try:
        client.request("initialize", {
            "protocolVersion": 1,
            "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False},
                                   "terminal": False},
        }, timeout=timeout)
        sids = []
        for session in sessions:
            sess = client.request("session/new", {"cwd": str(cwd),
                                                  "mcpServers": mcp_servers_for(session["servers"])},
                                  timeout=timeout)
            sid = sess["sessionId"]
            adapter.set_mode(client, sid, session.get("mode", "approve"), sess)
            sids.append(sid)
        threads = [threading.Thread(target=drive, args=(s, sid)) for s, sid in zip(sessions, sids)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        time.sleep(scenario.get("settle_seconds", 0.5))
    except ACPError as e:
        errors.append(str(e))
    finally:
        client.close()
        srv.shutdown()
    error = "; ".join(errors) or None

    ctx = {
        "server_log": read_jsonl(server_log),
        "model_log": read_jsonl(model_log),
        "permissions": client.permission_requests,
        "call_names": {},
        "workdir": str(cwd),
    }
    ctx["call_names"] = call_names(ctx["model_log"])
    results = []
    for a in scenario.get("expect", []):
        ok, detail = check(a, ctx)
        results.append({"assertion": a, "pass": ok, "detail": detail})
    agent_turns = len([r for r in ctx["model_log"] if r.get("kind") == "agent"])
    if error:
        status = "ERROR"
    elif agent_turns == 0:
        status = "ERROR"
        error = "the host never sent the scripted model an agent request (tools not attached?)"
    else:
        status = "PASS" if all(r["pass"] for r in results) else "FAIL"
    missing = sorted({r["answer"] for r in client.permission_requests
                      if r["answer"] is not None
                      and r["answer"] not in [o.get("optionId") for o in r["params"].get("options", [])]})
    if missing and status in ("PASS", "FAIL"):
        # the scenario needs an answer this host never offers, so it cannot judge the host
        status = "N/A"
        error = f"host does not offer the permission option(s) {missing}"
    record = {
        "id": scenario["id"], "title": scenario.get("title"), "host": host,
        "mode": scenario.get("mode") or sessions[0].get("mode", "approve"), "status": status, "error": error,
        "severity": scenario.get("severity"), "category": scenario.get("category"),
        "expected_by": scenario.get("expected_by"),
        "seconds": round(time.time() - started, 2), "agent_turns": agent_turns,
        "results": results,
    }
    case_dir = Path(out_dir) / host / scenario["id"]
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    (case_dir / "verdict.json").write_text(json.dumps(record, indent=2, ensure_ascii=False))
    (case_dir / "acp.json").write_text(json.dumps(transcript, indent=1, ensure_ascii=False))
    for name in ("server.jsonl", "model.jsonl", "host-stderr.log"):
        if (work / name).exists():
            shutil.copy(work / name, case_dir / name)
    shutil.rmtree(work, ignore_errors=True)
    return record


def load_scenarios(paths, only=None):
    scenarios = []
    for p in paths:
        p = Path(p)
        files = sorted(p.glob("*.json")) if p.is_dir() else [p]
        for f in files:
            s = json.loads(f.read_text(encoding="utf-8"))
            if only and not re.search(only, s["id"]):
                continue
            scenarios.append(s)
    return scenarios


def main(argv=None):
    ap = argparse.ArgumentParser(description="MCP host security gauntlet")
    ap.add_argument("--host", default="goose", choices=sorted(HOSTS))
    default_dirs = [str(HERE.parent / "scenarios")]
    if (HERE.parent / "embargoed" / "scenarios").is_dir():
        # scenarios for findings still under coordinated disclosure; not published
        default_dirs.append(str(HERE.parent / "embargoed" / "scenarios"))
    ap.add_argument("--scenarios", nargs="+", default=default_dirs)
    ap.add_argument("--only")
    ap.add_argument("--out", default="results")
    ap.add_argument("--timeout", type=float, default=90)
    args = ap.parse_args(argv)
    records = []
    for s in load_scenarios(args.scenarios, args.only):
        if s.get("hosts") and not any(args.host == h or args.host.startswith(h + "-") for h in s["hosts"]):
            continue
        modes = getattr(HOSTS[args.host], "modes", None)
        wanted = [x.get("mode", "approve") for x in s.get("sessions", [])] or [s.get("mode", "approve")]
        wanted += [p["set_mode"] for x in s.get("sessions", []) for p in x.get("prompts", [])
                   if isinstance(p, dict) and "set_mode" in p]
        if modes and any(m not in modes for m in wanted):
            continue  # the host has no equivalent of this approval mode
        rec = run_scenario(s, args.host, args.out, args.timeout)
        records.append(rec)
        print(f"{rec['status']:5} {rec['id']:40} {rec['seconds']:6.1f}s  "
              + "; ".join(r["detail"] for r in rec["results"] if not r["pass"])
              + (f" [{rec['error']}]" if rec["error"] else ""), flush=True)
    summary = Path(args.out) / args.host / "summary.json"
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps(records, indent=2, ensure_ascii=False))
    counts = {k: sum(1 for r in records if r["status"] == k) for k in ("PASS", "FAIL", "ERROR", "N/A")}
    print(json.dumps(counts))
    return 0 if counts["ERROR"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
