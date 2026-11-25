"""Host adapters: how to launch each agent host as an ACP server, pointed at
the scripted model, in an isolated config directory."""

import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _base_env(home):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GOOSE_", "OPENAI_", "ANTHROPIC_"))}
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
        return os.environ.get("GOOSE_BIN") or shutil.which("goose") or "goose"

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


HOSTS = {"goose": Goose(), "goose-anthropic": Goose("anthropic"), "reference": Reference()}
