# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         llm
# Purpose:      Provider-agnostic LLM client for llamaFoot. Free or local
#               providers only: Ollama (local), Ollama cloud, and the free tiers
#               of Groq, OpenRouter and Google Gemini.
# -------------------------------------------------------------------------------
"""LLM provider layer.

Every provider is one of two wire formats:

* ``ollama``: Ollama's native ``/api/chat`` (local daemon or ollama.com)
* ``openai``: OpenAI-compatible ``/chat/completions`` (Groq, OpenRouter, Gemini)

Base URLs are fixed per provider (the UI cannot point the server at an arbitrary
host), except for local Ollama which an administrator can move with the
``LLAMAFOOT_OLLAMA_HOST`` environment variable.

API keys come from environment variables first and from a ``0600`` JSON file in
the SpiderFoot data directory second. Keys are never returned to the browser.
"""

from __future__ import annotations

import json
import logging
import os
import typing

import requests

log = logging.getLogger(f"spiderfoot.{__name__}")

CONFIG_FILENAME = "llamafoot_llm.json"
DEFAULT_TIMEOUT = 120


class LLMError(Exception):
    """Raised for any provider, configuration or network failure."""


PROVIDERS: typing.Dict[str, typing.Dict[str, typing.Any]] = {
    "ollama_local": {
        "name": "Ollama (local)",
        "badge": "Free · Local",
        "wire": "ollama",
        "base_url": "http://127.0.0.1:11434",
        "base_url_env": "LLAMAFOOT_OLLAMA_HOST",
        "key_env": None,
        "default_model": "",
        "tooltip": (
            "Runs on the same machine as llamaFoot. Nothing leaves the server.\n"
            "1. Install Ollama from https://ollama.com/download\n"
            "2. Pull a model, e.g. ollama pull llama3.2\n"
            "3. Leave Ollama running (port 11434), then pick the model here.\n"
            "Large models are slow without a GPU. Cloud models (names ending in :cloud) also work here "
            "after you run ollama signin on the server.\n"
            "Different host? Set LLAMAFOOT_OLLAMA_HOST on the server."
        ),
    },
    "ollama_cloud": {
        "name": "Ollama Cloud",
        "badge": "Free tier · Cloud",
        "wire": "ollama",
        "base_url": "https://ollama.com",
        "base_url_env": None,
        "key_env": "OLLAMA_API_KEY",
        "default_model": "gemma4:31b",
        "tooltip": (
            "Fast on any computer, no download. Runs on Ollama's servers, so scan summaries are sent to them.\n"
            "1. Create a free account at https://ollama.com\n"
            "2. Create an API key at https://ollama.com/settings/keys\n"
            "3. Paste it here, or set OLLAMA_API_KEY on the server.\n"
            "Use the exact model name from the model list (no :cloud suffix over the API). "
            "Which models the free plan includes and its limits are set by Ollama and can change."
        ),
    },
    "groq": {
        "name": "Groq",
        "badge": "Free tier · Cloud",
        "wire": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "base_url_env": None,
        "key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "tooltip": (
            "Very fast hosted open models. Scan summaries are sent to Groq.\n"
            "1. Sign up at https://console.groq.com\n"
            "2. Create an API key (the free tier needs no card)\n"
            "3. Paste it here, or set GROQ_API_KEY on the server.\n"
            "Rate limits are set by Groq and can change."
        ),
    },
    "openrouter": {
        "name": "OpenRouter (free models)",
        "badge": "Free models · Cloud",
        "wire": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "base_url_env": None,
        "key_env": "OPENROUTER_API_KEY",
        "default_model": "meta-llama/llama-3.3-70b-instruct:free",
        "tooltip": (
            "One key, many models. Only pick models whose id ends in :free or you may be billed.\n"
            "1. Sign up at https://openrouter.ai\n"
            "2. Create an API key at https://openrouter.ai/keys\n"
            "3. Paste it here, or set OPENROUTER_API_KEY on the server.\n"
            "Free model availability and limits change often. Scan summaries are sent to the model host."
        ),
    },
    "gemini": {
        "name": "Google Gemini",
        "badge": "Free tier · Cloud",
        "wire": "openai",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "base_url_env": None,
        "key_env": "GEMINI_API_KEY",
        "default_model": "gemini-2.5-flash",
        "tooltip": (
            "Google's free API tier. Scan summaries are sent to Google and, on the free tier, "
            "may be used to improve their products.\n"
            "1. Create a key at https://aistudio.google.com/apikey\n"
            "2. Paste it here, or set GEMINI_API_KEY on the server.\n"
            "Free tier limits are set by Google and can change."
        ),
    },
}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _config_path() -> str:
    from spiderfoot import SpiderFootHelpers
    return os.path.join(SpiderFootHelpers.dataPath(), CONFIG_FILENAME)


def _read_config() -> typing.Dict[str, typing.Any]:
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def ui_writes_disabled() -> bool:
    """True when the administrator has locked LLM settings to environment variables."""
    return os.environ.get("LLAMAFOOT_LLM_READONLY", "").lower() in ("1", "true", "yes")


def save_config(provider: str, model: str = "", api_key: typing.Optional[str] = None) -> None:
    """Persist the chosen provider, model and (optionally) an API key.

    Args:
        provider: provider id
        model: model name; blank means the provider default
        api_key: key to store for this provider; None keeps the existing one, "" clears it

    Raises:
        LLMError: unknown provider, locked configuration or write failure
    """
    if ui_writes_disabled():
        raise LLMError("LLM settings are locked by the server administrator (LLAMAFOOT_LLM_READONLY).")
    if provider not in PROVIDERS:
        raise LLMError(f"Unknown provider: {provider}")
    model = (model or "").strip()
    if len(model) > 200 or any(c in model for c in "\r\n\t"):
        raise LLMError("Invalid model name.")

    cfg = _read_config()
    cfg["provider"] = provider
    cfg.setdefault("models", {})[provider] = model
    if api_key is not None:
        keys = cfg.setdefault("keys", {})
        api_key = api_key.strip()
        if api_key:
            if len(api_key) > 512 or any(c.isspace() for c in api_key):
                raise LLMError("Invalid API key.")
            keys[provider] = api_key
        else:
            keys.pop(provider, None)

    path = _config_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        os.chmod(path, 0o600)
    except OSError as e:
        raise LLMError(f"Could not save settings: {e}") from e


def _api_key(provider: str) -> str:
    env = PROVIDERS[provider]["key_env"]
    if env and os.environ.get(env):
        return os.environ[env].strip()
    return str(_read_config().get("keys", {}).get(provider, "")).strip()


def _base_url(provider: str) -> str:
    p = PROVIDERS[provider]
    env = p.get("base_url_env")
    url = os.environ.get(env, "") if env else ""
    return (url or p["base_url"]).rstrip("/")


def active_selection() -> typing.Tuple[typing.Optional[str], str]:
    """Return the currently selected (provider, model); provider is None if nothing is chosen."""
    cfg = _read_config()
    provider = cfg.get("provider")
    if provider not in PROVIDERS:
        env_provider = os.environ.get("LLAMAFOOT_LLM_PROVIDER", "")
        provider = env_provider if env_provider in PROVIDERS else None
    if provider is None:
        return None, ""
    model = cfg.get("models", {}).get(provider) or os.environ.get("LLAMAFOOT_LLM_MODEL", "") or PROVIDERS[provider]["default_model"]
    return provider, model


def list_providers() -> typing.List[typing.Dict[str, typing.Any]]:
    """Describe every provider for the UI. Never includes key material."""
    provider, model = active_selection()
    out = []
    for pid, p in PROVIDERS.items():
        needs_key = bool(p["key_env"])
        cfg_model = _read_config().get("models", {}).get(pid) or p["default_model"]
        out.append({
            "id": pid,
            "name": p["name"],
            "badge": p["badge"],
            "local": pid == "ollama_local",
            "needs_key": needs_key,
            "key_env": p["key_env"],
            "key_configured": bool(_api_key(pid)) if needs_key else None,
            "model": cfg_model,
            "tooltip": p["tooltip"],
            "selected": pid == provider,
        })
    return out


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------

def _headers(provider: str) -> typing.Dict[str, str]:
    h = {"Content-Type": "application/json"}
    key = _api_key(provider)
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h


def _require_ready(provider: str) -> None:
    if provider not in PROVIDERS:
        raise LLMError(f"Unknown provider: {provider}")
    if PROVIDERS[provider]["key_env"] and not _api_key(provider):
        raise LLMError(f"{PROVIDERS[provider]['name']} needs an API key. Open the AI settings tooltip for setup steps.")


def list_models(provider: str, timeout: int = 15) -> typing.List[str]:
    """List model names the provider offers (best effort)."""
    _require_ready(provider)
    p = PROVIDERS[provider]
    base = _base_url(provider)
    try:
        if p["wire"] == "ollama":
            r = requests.get(f"{base}/api/tags", headers=_headers(provider), timeout=timeout, allow_redirects=False)
            r.raise_for_status()
            return sorted(m.get("name") or m.get("model") for m in r.json().get("models", []) if m.get("name") or m.get("model"))
        r = requests.get(f"{base}/models", headers=_headers(provider), timeout=timeout, allow_redirects=False)
        r.raise_for_status()
        ids = [m.get("id", "") for m in r.json().get("data", [])]
        ids = [i.replace("models/", "", 1) for i in ids if i]
        if provider == "openrouter":
            ids = [i for i in ids if i.endswith(":free")]
        return sorted(ids)
    except requests.exceptions.ConnectionError as e:
        raise LLMError(_unreachable(provider)) from e
    except requests.exceptions.RequestException as e:
        raise LLMError(f"Could not list models: {_http_reason(e)}") from e
    except ValueError as e:
        raise LLMError("The provider returned an unreadable model list.") from e


def _unreachable(provider: str) -> str:
    if provider == "ollama_local":
        return "Could not reach Ollama on this server. Is it installed and running? (See the tooltip for setup steps.)"
    return f"Could not reach {PROVIDERS[provider]['name']}."


def _http_reason(e: Exception) -> str:
    resp = getattr(e, "response", None)
    if resp is not None:
        if resp.status_code in (401, 403):
            return "the API key was rejected"
        if resp.status_code == 404:
            return "model or endpoint not found (check the model name)"
        if resp.status_code == 429:
            return "rate limit reached on the free tier, try again later"
        return f"HTTP {resp.status_code}"
    return type(e).__name__


def chat(messages: typing.List[typing.Dict[str, str]], provider: typing.Optional[str] = None,
         model: typing.Optional[str] = None, json_mode: bool = False, temperature: float = 0.2,
         timeout: int = DEFAULT_TIMEOUT) -> str:
    """Send a chat completion and return the assistant text.

    Args:
        messages: list of ``{"role": ..., "content": ...}``
        provider: provider id; defaults to the saved selection
        model: model name; defaults to the saved model for that provider
        json_mode: ask the model for a JSON object
        temperature: sampling temperature
        timeout: request timeout in seconds

    Returns:
        str: the model's reply

    Raises:
        LLMError: not configured, unreachable, rejected or malformed response
    """
    sel_provider, sel_model = active_selection()
    provider = provider or sel_provider
    if not provider:
        raise LLMError("No AI provider selected. Choose one in the AI settings.")
    _require_ready(provider)
    if model is None or not model.strip():
        model = sel_model if provider == sel_provider else PROVIDERS[provider]["default_model"]
    if not model:
        raise LLMError("No model selected. Pick a model in the AI settings.")

    p = PROVIDERS[provider]
    base = _base_url(provider)
    try:
        if p["wire"] == "ollama":
            body: typing.Dict[str, typing.Any] = {"model": model, "messages": messages, "stream": False,
                                                  "options": {"temperature": temperature}}
            if json_mode:
                body["format"] = "json"
            r = requests.post(f"{base}/api/chat", headers=_headers(provider), json=body, timeout=timeout, allow_redirects=False)
            r.raise_for_status()
            return str(r.json()["message"]["content"]).strip()

        body = {"model": model, "messages": messages, "temperature": temperature}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        r = requests.post(f"{base}/chat/completions", headers=_headers(provider), json=body, timeout=timeout, allow_redirects=False)
        r.raise_for_status()
        return str(r.json()["choices"][0]["message"]["content"]).strip()
    except requests.exceptions.ConnectionError as e:
        raise LLMError(_unreachable(provider)) from e
    except requests.exceptions.Timeout as e:
        raise LLMError("The model took too long to answer. Try a smaller model or a cloud provider.") from e
    except requests.exceptions.RequestException as e:
        raise LLMError(f"{p['name']} request failed: {_http_reason(e)}") from e
    except (KeyError, IndexError, ValueError, TypeError) as e:
        raise LLMError(f"{p['name']} returned an unexpected response.") from e


def test_connection(provider: str, model: typing.Optional[str] = None) -> str:
    """Make a tiny request to prove the provider, key and model work. Returns the reply."""
    return chat([{"role": "user", "content": "Reply with the single word: ready"}],
                provider=provider, model=model, timeout=60)
