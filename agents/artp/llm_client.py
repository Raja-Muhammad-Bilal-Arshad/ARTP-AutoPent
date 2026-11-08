# agents/artp/llm_client.py
import os
import json
import subprocess
import shlex
import logging

logger = logging.getLogger(__name__)

def call_local_model(model: str, prompt: str, timeout: int = 25):
    """
    Uses 'ollama' CLI if available. Falls back with an informative error.
    Adjust this function to call your local LLM runtime if it's not ollama.
    """
    # require ollama to be installed and model to exist locally
    ollama = shutil.which("ollama")
    if not ollama:
        raise RuntimeError("Local mode requested but 'ollama' CLI not found. Install Ollama or change local_call.")
    # build command
    cmd = f"ollama run {shlex.quote(model)} --prompt-file /dev/stdin"
    # run
    p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(prompt, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"Local model call failed: {p.returncode}, stderr={err.strip()}")
    return out

def call_openai_api(model: str, prompt: str, max_tokens: int = 1024, temperature: float = 0.0):
    try:
        import openai
    except Exception as e:
        raise RuntimeError("openai package not installed. Install 'openai' to use API mode.") from e
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment.")
    openai.api_key = api_key
    # Use chat completions if model supports; fallback to text completion
    try:
        resp = openai.ChatCompletion.create(
            model=model,
            messages=[{"role":"user","content":prompt}],
            temperature=temperature,
            max_tokens=max_tokens
        )
        return resp.choices[0].message.content
    except Exception as e:
        # try legacy completion
        resp = openai.Completion.create(model=model, prompt=prompt, temperature=temperature, max_tokens=max_tokens)
        return resp.choices[0].text

def generate(prompt: str, model: str = "gpt-4o", mode: str = "api", **kwargs) -> str:
    """
    Main entry. mode="api" or "local".
    Returns raw string output produced by the LLM.
    """
    mode = mode.lower()
    if mode == "api":
        return call_openai_api(model, prompt, **kwargs)
    elif mode == "local":
        # attempt to use ollama CLI
        import shutil
        ollama = shutil.which("ollama")
        if ollama:
            # write prompt to stdin of ollama
            return call_local_model(model, prompt, **kwargs)
        else:
            raise RuntimeError("Local mode requested but no local runner found (ollama CLI not present).")
    else:
        raise ValueError("Unknown LLM mode: choose 'api' or 'local'.")

