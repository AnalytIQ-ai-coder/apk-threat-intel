"""Scan samples with the YARA rules in yara_rules/.

These rules cover families and campaigns we identified by hand in earlier
reports (see custom_families.yar) rather than relying on MobSF's classification
alone.

If yara-python is not installed the module degrades to a no-op and returns an
empty list, so a missing optional dependency never blocks the pipeline.
"""
import os
import zipfile

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

_compiled = None
# Files that failed to compile, kept around so callers can ask about them.
_broken_files = []


def _compile_rules():
    """Compile the rules file by file, skipping any with a syntax error.

    Everything used to go into a single yara.compile(), so one typo in one rule
    took down the WHOLE set: scan() quietly returned an empty list and YARA
    detection disappeared without anyone noticing. Now a broken file costs only
    itself, and it says so loudly.
    """
    global _compiled, _broken_files
    if _compiled is not None:
        return _compiled
    if not _YARA_AVAILABLE or not os.path.isdir(RULES_DIR):
        _compiled = False
        return _compiled

    names = sorted(n for n in os.listdir(RULES_DIR) if n.endswith((".yar", ".yara")))
    if not names:
        print("[yara_scanner] WARNING: no rule files in %s" % RULES_DIR)
        _compiled = False
        return _compiled

    good, _broken_files = {}, []
    for name in names:
        path = os.path.join(RULES_DIR, name)
        try:
            yara.compile(filepath=path)          # validate this file on its own
            good[name] = path
        except Exception as e:
            _broken_files.append((name, str(e)))
            print("[yara_scanner] !!! SKIPPED rule %s, syntax error: %s" % (name, e))

    if not good:
        print("[yara_scanner] !!! no rule compiled at all, YARA detection is OFF")
        _compiled = False
        return _compiled

    try:
        _compiled = yara.compile(filepaths=good)
    except Exception as e:                       # should not happen after validation
        print("[yara_scanner] !!! failed to link rules: %s, YARA detection is OFF" % e)
        _compiled = False
        return _compiled

    rule_count = sum(1 for _ in _compiled)
    print("[yara_scanner] loaded %d rules from %d files%s" % (
        rule_count, len(good),
        (" (SKIPPED %d broken)" % len(_broken_files)) if _broken_files else ""))
    return _compiled


def broken_rule_files():
    """(filename, error) for every file skipped during the last compile."""
    _compile_rules()
    return list(_broken_files)


# An APK is a ZIP and its entries are DEFLATEd. YARA handed a file path sees
# the compressed bytes, so NO string from classes.dex can ever match. Confirmed
# by experiment (same marker: a STORED entry hits, a DEFLATEd one does not) and
# by production data: 38 of 38 samples had empty yara_matches with 13 rules
# loaded. Hence the second pass over decompressed content.
#
# The raw pass is NOT replaced by it: the v2/v3 signature block lives outside
# the ZIP entries, uncompressed, and that is what the RSA-modulus rules in
# campaign_certs.yar match against.
_MAX_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024

# Entries carrying the strings rules rely on: code (dex), the manifest,
# resources (the app label), payloads in assets/ and native libraries.
_SCANNED_EXTENSIONS = (".dex", ".arsc", ".so")
_SCANNED_NAMES = ("androidmanifest.xml",)
_SCANNED_PREFIXES = ("assets/",)


def _entry_worth_scanning(name: str) -> bool:
    """Is this ZIP entry one of the kinds our rules look at?"""
    n = name.lower()
    return (n.endswith(_SCANNED_EXTENSIONS)
            or n.rsplit("/", 1)[-1] in _SCANNED_NAMES
            or n.startswith(_SCANNED_PREFIXES))


def _decompressed_content(apk_path: str) -> bytes:
    """Glue the decompressed APK entries into one buffer to scan.

    The caps match dex_analyzer's, for the same reason: the declared file_size
    in a crafted archive can lie, so the limit is enforced at read time too. A
    single unreadable entry is skipped - scanning part of a sample beats
    scanning none of it.
    """
    chunks, total = [], 0
    try:
        with zipfile.ZipFile(apk_path) as z:
            for info in z.infolist():
                if info.is_dir() or not _entry_worth_scanning(info.filename):
                    continue
                if info.file_size > _MAX_ENTRY_BYTES:
                    continue
                remaining = _MAX_TOTAL_BYTES - total
                if remaining <= 0:
                    break
                try:
                    with z.open(info) as fh:
                        data = fh.read(min(_MAX_ENTRY_BYTES, remaining) + 1)
                except Exception as e:
                    # An entry zipfile cannot unpack. Android is far more
                    # forgiving and installs these happily, so this is not a
                    # "corrupt file" - it is an anti-analysis technique, and an
                    # effective one: EVERY rule resting on strings from this
                    # entry silently fails to fire.
                    #
                    # Two confirmed variants among samples in the database:
                    #   * a non-standard compression method (0, 8, 9, 12, 14 are
                    #     legal) - the Venom sample declared AndroidManifest.xml
                    #     with method 17180 in the central directory and 32040 in
                    #     the local header (NotImplementedError),
                    #   * general-purpose bit 0 set, i.e. "entry is encrypted" -
                    #     the tiktok18/MetaMask cluster, where one sample marked
                    #     classes.dex and AndroidManifest.xml and another marked
                    #     EVERY entry, leaving the content buffer completely
                    #     empty (RuntimeError "File is encrypted").
                    # Details in yara_rules/venom_tools.yar and metamask_loader.yar.
                    #
                    # We catch broadly (Exception) because the list of tricks is
                    # open-ended and they all present identically: silence that
                    # is indistinguishable from "no match". The raw bytes are
                    # not appended as a consolation - the raw pass already sees
                    # them, so there is nothing to gain and noise to lose.
                    print("[yara_scanner] WARNING: cannot unpack %s (%s, method %d,"
                          " flags 0x%04x) - skipped in the content pass, rules"
                          " resting on its strings WILL NOT fire on this sample"
                          % (info.filename, type(e).__name__, info.compress_type,
                             info.flag_bits))
                    continue
                if len(data) > remaining:
                    break
                chunks.append(data)
                total += len(data)
    except Exception:
        return b""
    # A NUL between entries stops a string from matching across the seam.
    return bytes([0]).join(chunks)


def scan(apk_path: str) -> list[dict]:
    """Return {rule, family, description} for every matching custom YARA rule."""
    rules = _compile_rules()
    if not rules:
        return []

    try:
        matches = list(rules.match(apk_path))     # raw bytes: the v2/v3 signature block
    except Exception as e:
        print(f"[yara_scanner] error scanning {apk_path}: {e}")
        return []

    content = _decompressed_content(apk_path)
    if content:
        try:
            matches += list(rules.match(data=content))
        except Exception as e:
            print(f"[yara_scanner] error scanning content of {apk_path}: {e}")

    results, seen = [], set()
    for m in matches:
        if m.rule in seen:      # same rule hit by both passes
            continue
        seen.add(m.rule)
        results.append({
            "rule": m.rule,
            "family": m.meta.get("family", m.rule),
            "description": m.meta.get("description", ""),
        })
    return results


def available() -> bool:
    """Is yara-python importable?"""
    return _YARA_AVAILABLE


def scan_isolated(apk_path: str, timeout: int = 60) -> list[dict]:
    """scan() in a child process under a hard deadline.

    libyara is native C parsing an attacker-controlled file. A bug in there does
    not surface as a Python exception but as memory corruption or a spin. A
    separate process means the worst case is losing YARA results for one sample.
    """
    from isolation import run_isolated, IsolationTimeout, IsolationError
    try:
        return run_isolated(scan, (apk_path,), timeout=timeout)
    except IsolationTimeout as e:
        print(f"[yara_scanner] scan aborted: {e}")
        return []
    except IsolationError as e:
        print(f"[yara_scanner] error: {str(e).splitlines()[-1]}")
        return []
