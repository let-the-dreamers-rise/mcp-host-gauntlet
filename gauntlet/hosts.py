"""Host adapters: how to launch each agent host as an ACP server, pointed at
the scripted model, in an isolated config directory."""

import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _base_env(home):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GOOSE_", "OPENAI_", "ANTHROPIC_", "OLLAMA_", "LITELLM_", "OPENROUTER_"))}
    env["HOME"] = home
    env["XDG_CONFIG_HOME"] = os.path.join(home, ".config")
    env["XDG_DATA_HOME"] = os.path.join(home, ".local", "share")
    env["XDG_STATE_HOME"] = os.path.join(home, ".local", "state")
    return env


class Goose:
    name = "goose"

    def __init__(self, provider="openai"):
        self.provider = provider

    @staticmethod
    def binary():
        b = os.environ.get("GOOSE_BIN")
        if b:
            return os.path.abspath(b)
        return shutil.which("goose") or "goose"

    def command(self, home, llm_url, mode):
        env = _base_env(home)
        env.update({
            "GOOSE_PATH_ROOT": home,
            "GOOSE_DISABLE_KEYRING": "1",
            "GOOSE_MODE": mode,
            "GOOSE_TELEMETRY_ENABLED": "false",
            "GOOSE_DISABLE_SESSION_NAMING": "true",
        })
        if self.provider == "anthropic":
            env.update({"GOOSE_PROVIDER": "anthropic", "GOOSE_MODEL": "claude-gauntlet",
                        "ANTHROPIC_API_KEY": "gauntlet", "ANTHROPIC_HOST": llm_url})
        elif self.provider in ("ollama", "litellm", "openrouter"):
            up = self.provider.upper()
            env.update({"GOOSE_PROVIDER": self.provider, "GOOSE_MODEL": "gauntlet-model",
                        up + "_API_KEY": "gauntlet", up + "_HOST": llm_url})
        else:
            env.update({"GOOSE_PROVIDER": "openai", "GOOSE_MODEL": "gauntlet-model",
                        "OPENAI_API_KEY": "gauntlet", "OPENAI_HOST": llm_url})
        return [self.binary(), "acp"], env

    def set_mode(self, client, session_id, mode, session_response):
        modes = (session_response or {}).get("modes") or {}
        current = modes.get("currentModeId")
        if current == mode:
            return
        available = [m.get("id") for m in modes.get("availableModes", [])]
        if mode in available:
            client.request("session/set_mode", {"sessionId": session_id, "modeId": mode})


class OpenCode:
    """opencode (https://opencode.ai) as an ACP agent: `opencode acp`, pointed
    at the scripted model through an OpenAI-compatible custom provider."""

    name = "opencode"
    modes = ("approve", "auto")

    @staticmethod
    def binary():
        b = os.environ.get("OPENCODE_BIN")
        return os.path.abspath(b) if b else (shutil.which("opencode") or "opencode")

    def command(self, home, llm_url, mode):
        import json
        env = _base_env(home)
        env["OPENCODE_DISABLE_AUTOUPDATE"] = "1"
        cfg = {
            "$schema": "https://opencode.ai/config.json",
            "autoupdate": False,
            "share": "disabled",
            "provider": {"gauntlet": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "gauntlet",
                "options": {"baseURL": llm_url + "/v1", "apiKey": "gauntlet"},
                "models": {"gauntlet-model": {"name": "gauntlet-model", "tool_call": True}},
            }},
            "model": "gauntlet/gauntlet-model",
            "small_model": "gauntlet/gauntlet-model",
            "permission": {"*": "allow" if mode == "auto" else "ask"},
        }
        d = Path(home) / ".config" / "opencode"
        d.mkdir(parents=True, exist_ok=True)
        (d / "opencode.json").write_text(json.dumps(cfg, indent=2))
        return [self.binary(), "acp"], env

    def set_mode(self, client, session_id, mode, session_response):
        return


class Reference:
    """The bundled reference host (gauntlet/reference_host.py): a small,
    deliberately strict ACP host used to self-test the oracles in CI.
    REFERENCE_FLAWS=comma,list switches on known-bad behaviours so the tests
    can prove each scenario fails when the host is wrong."""

    name = "reference"

    def command(self, home, llm_url, mode):
        env = _base_env(home)
        env["REF_LLM_URL"] = llm_url
        env["REF_MODE"] = mode
        return [sys.executable, str(HERE / "reference_host.py")], env

    def set_mode(self, client, session_id, mode, session_response):
        client.request("session/set_mode", {"sessionId": session_id, "modeId": mode})


HOSTS = {"opencode": OpenCode(), "goose": Goose(), "goose-anthropic": Goose("anthropic"),
         "goose-ollama": Goose("ollama"), "goose-litellm": Goose("litellm"),
         "goose-openrouter": Goose("openrouter"), "reference": Reference()}
