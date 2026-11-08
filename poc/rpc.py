"""JSON-RPC process isolation (paper Sec. 4.1: 'strict process isolation by
JSON-RPC').

The planner/pipeline process talks to a *child process* running
``python3 -m poc.rpc --seed N`` over line-delimited JSON-RPC 2.0 on stdio.
Every engagement (session) gets its own fresh executor process; crashing or
compromising one session cannot leak state into the next.

Methods
--------
initialize    {scenario}                       -> {session, node_count, ...}
exec.action   {step}                           -> per-step observation record
exec.finish   {}                               -> session summary
shutdown      {}                               -> {ok: true} then exit
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# server side (child process)
# ---------------------------------------------------------------------------
def serve(seed: int) -> int:
    from .executor import SimExecutor
    from .state import Surface, DEMO_STATES

    executor: Optional[SimExecutor] = None
    next_id = 0
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        next_id += 1
        req: Dict[str, Any] = {}
        try:
            req = json.loads(raw)
            method, params, rid = req.get("method"), req.get("params") or {}, \
                req.get("id", next_id)
            if method == "initialize":
                st = params.get("state")
                if st:
                    # caller-supplied state (real-lab export / custom sandbox):
                    # the child process is isolated around THIS topology
                    state = st
                else:
                    state = DEMO_STATES[params["scenario"]]()
                surf = Surface(state)
                executor = SimExecutor(seed, surf)
                resp = {"session": executor.session,
                        "scenario": surf.scenario,
                        "n_nodes": len(surf.nodes),
                        "policies": surf.policies}
            elif method == "exec.action":
                assert executor is not None, "call initialize first"
                resp = executor.execute_step(params["step"])
            elif method == "exec.finish":
                assert executor is not None, "call initialize first"
                resp = executor.summary()
            elif method == "shutdown":
                _send({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}})
                return 0
            else:
                resp = None
                _send({"jsonrpc": "2.0", "id": rid, "error":
                       {"code": -32601, "message": "method not found"}})
                continue
            _send({"jsonrpc": "2.0", "id": rid, "result": resp})
        except Exception as exc:  # never crash the protocol loop silently
            _send({"jsonrpc": "2.0", "id": req.get("id", next_id) if
                   isinstance(req, dict) else next_id,
                   "error": {"code": -32000, "message": repr(exc)}})
    return 0


def _send(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, default=str) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# client side (parent process)
# ---------------------------------------------------------------------------
class RPCClient:
    """Spawn + drive the isolated executor process."""

    def __init__(self, seed: int, repo_root: Optional[str] = None):
        self.seed = seed
        self.proc: Optional[subprocess.Popen] = None
        self.repo_root = repo_root or os.getcwd()
        self._id = 0

    # ------------------------------------------------------------------
    def _spawn(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = self.repo_root + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "poc.rpc", "--seed", str(self.seed)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, cwd=self.repo_root, text=True,
            bufsize=1)

    def call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        assert self.proc is not None and self.proc.stdin and self.proc.stdout
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method,
               "params": params}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("RPC executor process died before responding "
                               "(method={})".format(method))
        resp = json.loads(line)
        if "error" in resp:
            raise RuntimeError("RPC error from {}: {}".format(method,
                                                              resp["error"]))
        return resp["result"]

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.call("shutdown", {})
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass
        self.proc.wait(timeout=10)
        self.proc = None

    def __enter__(self) -> "RPCClient":
        self._spawn()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def run_session(seed: int, scenario: str,
                steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convenience driver: full session = initialize -> exec.action* -> finish."""
    trace: List[Dict[str, Any]] = []
    with RPCClient(seed) as rpc:
        info = rpc.call("initialize", {"scenario": scenario})
        terminated = False
        for step in steps:
            if terminated:
                trace.append({"step_id": step.get("step_id"), "skipped": True,
                              "reason": "session terminated after detection"})
                continue
            res = rpc.call("exec.action", {"step": step})
            trace.append(res)
            if res.get("terminated_session") or res.get("terminated"):
                terminated = True
        summary = rpc.call("exec.finish", {})
    return {"session": info, "trace": trace, "summary": summary}


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="ARTP PoC isolated executor (JSON-RPC over stdio)")
    ap.add_argument("--seed", type=int, required=True)
    args = ap.parse_args()
    return serve(args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
