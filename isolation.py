"""Run parsers for untrusted files in a separate process.

An APK is hostile input. A crafted DEX or AXML can hang androguard's parser
forever (a deliberate anti-analysis trick) or eat all available memory. Calling
into it from a child process with a hard timeout means the worst case is losing
one sample, not wedging the whole run.

The "spawn" context is deliberate: fork does not exist on Windows, and a clean
child start means androguard's global state is not inherited from the parent.
"""
import multiprocessing as mp
import queue as _queue
import traceback


class IsolationTimeout(Exception):
    """The worker process ran past its deadline and was killed."""


class IsolationError(Exception):
    """The function raised inside the worker process."""


def _worker(target, args, kwargs, q) -> None:
    try:
        q.put(("ok", target(*args, **(kwargs or {}))))
    except Exception:
        q.put(("err", traceback.format_exc(limit=3)))


def run_isolated(target, args=(), kwargs=None, timeout: int = 90):
    """Call target(*args, **kwargs) in a child process and return its result.

    target has to be a module-level function in an importable module — the
    spawn context pickles it by reference, not by value.

    Raises IsolationTimeout if the deadline passes (the process is killed) or
    IsolationError if the function itself raised.
    """
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_worker, args=(target, args, kwargs, q), daemon=True)
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        p.join(5)
        if p.is_alive():  # terminate can be ignored when native code is spinning
            p.kill()
            p.join()
        raise IsolationTimeout(f"exceeded the {timeout}s limit")

    # Careful: q.empty() can read True even though a result was written —
    # multiprocessing.Queue's feeder thread may not have flushed to the pipe yet.
    try:
        status, payload = q.get(timeout=10)
    except _queue.Empty:
        raise IsolationError("worker process exited without producing a result")

    if status == "err":
        raise IsolationError(payload)
    return payload
