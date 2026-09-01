"""Uruchamianie parserow niezaufanych plikow w osobnym procesie.

APK jest wrogim wejsciem. Spreparowany DEX albo AXML potrafi zawiesic parser
androguarda w nieskonczonosc (technika anty-analizy) lub wyczerpac pamiec.
Wywolanie w osobnym procesie z twardym limitem czasu sprawia, ze najgorszym
przypadkiem jest utrata jednej probki, a nie zawieszenie calego runu.

Kontekst "spawn" jest uzywany swiadomie: fork nie istnieje na Windowsie, a
czysty start procesu potomnego nie dziedziczy stanu androguarda z rodzica.
"""
import multiprocessing as mp
import queue as _queue
import traceback


class IsolationTimeout(Exception):
    """Proces roboczy przekroczyl limit czasu i zostal ubity."""


class IsolationError(Exception):
    """Funkcja w procesie roboczym zakonczyla sie bledem."""


def _worker(target, args, kwargs, q) -> None:
    try:
        q.put(("ok", target(*args, **(kwargs or {}))))
    except Exception:
        q.put(("err", traceback.format_exc(limit=3)))


def run_isolated(target, args=(), kwargs=None, timeout: int = 90):
    """Wywoluje target(*args, **kwargs) w osobnym procesie i zwraca wynik.

    target musi byc funkcja najwyzszego poziomu w importowalnym module —
    kontekst spawn przekazuje ja przez pickle po referencji.

    Podnosi IsolationTimeout po przekroczeniu limitu (proces jest wtedy
    ubijany) albo IsolationError, gdy funkcja rzucila wyjatkiem.
    """
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_worker, args=(target, args, kwargs, q), daemon=True)
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        p.join(5)
        if p.is_alive():  # terminate bywa ignorowane przy zapetleniu w kodzie natywnym
            p.kill()
            p.join()
        raise IsolationTimeout(f"przekroczono limit {timeout}s")

    # Uwaga: q.empty() bywa chwilowo True mimo zapisanego wyniku — watek feedera
    # multiprocessing.Queue moze nie zdazyc oproznic bufora do potoku.
    try:
        status, payload = q.get(timeout=10)
    except _queue.Empty:
        raise IsolationError("proces roboczy zakonczyl sie bez wyniku")

    if status == "err":
        raise IsolationError(payload)
    return payload
