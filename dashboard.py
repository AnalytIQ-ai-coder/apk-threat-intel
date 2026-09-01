"""Local web dashboard

Running:  python dashboard.py  (defualt http://localhost:5001)
"""
from urllib.parse import quote

from flask import Flask, render_template_string, request
from markupsafe import escape

import threat_db

app = Flask(__name__)


def h(value) -> str:
    """Escapuje wartosc do wstawienia w tresc HTML.

    Wszystko, co trafia do bazy, pochodzi z analizowanych probek: app_name,
    package, filename, cert_subject i wartosci IOC sa kontrolowane przez autora
    APK. Bez tego zlosliwa nazwa aplikacji wykonuje sie jako JS w tym dashboardzie.
    """
    return str(escape("" if value is None else str(value)))


def u(value) -> str:
    """Escapuje wartosc do wstawienia w URL (href)."""
    return quote(str(value or ""), safe="")

_LAYOUT = """
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>APK Threat Intel Dashboard</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #0f1117; color: #d7dae0;
         margin: 0; padding: 0 24px 40px; }
  h1 { font-size: 20px; padding: 20px 0 8px; }
  a { color: #7db4ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  nav { padding: 10px 0; border-bottom: 1px solid #2a2d38; margin-bottom: 20px; }
  nav a { margin-right: 16px; font-weight: 600; }
  .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .stat-card { background: #1a1d27; border: 1px solid #2a2d38; border-radius: 8px;
               padding: 14px 20px; min-width: 140px; }
  .stat-card .num { font-size: 24px; font-weight: 700; color: #ff6b6b; }
  .stat-card .label { font-size: 12px; color: #8b8f9c; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2d38; }
  th { color: #8b8f9c; text-transform: uppercase; font-size: 11px; }
  tr:hover { background: #1a1d27; }
  .risk-high, .risk-critical { color: #ff6b6b; font-weight: 600; }
  .risk-medium { color: #f5c518; }
  .risk-low { color: #6bd47a; }
  form.search { margin-bottom: 20px; }
  input[type=text] { background: #1a1d27; border: 1px solid #2a2d38; color: #d7dae0;
                      padding: 8px 12px; border-radius: 6px; width: 320px; }
  button { background: #2a5adf; color: white; border: none; padding: 8px 16px;
           border-radius: 6px; cursor: pointer; margin-left: 6px; }
  code { background: #1a1d27; padding: 2px 5px; border-radius: 4px; }
</style>
</head>
<body>
<nav>
  <a href="/">Przegląd</a>
  <a href="/search">Szukaj IOC</a>
</nav>
{{ content|safe }}
</body>
</html>
"""


def _render(content: str):
    return render_template_string(_LAYOUT, content=content)


@app.route("/")
def index():
    stats = threat_db.stats()
    samples = threat_db.recent_samples(limit=50)
    reused = threat_db.top_reused_iocs(limit=15)

    stats_html = f"""
    <h1>Przegląd</h1>
    <div class="stats">
      <div class="stat-card"><div class="num">{stats['samples']}</div><div class="label">Próbek</div></div>
      <div class="stat-card"><div class="num">{stats['unique_iocs']}</div><div class="label">Unikalnych IOC</div></div>
      <div class="stat-card"><div class="num">{stats['unique_certs']}</div><div class="label">Certów</div></div>
      <div class="stat-card"><div class="num">{stats['duplicates_skipped']}</div><div class="label">Duplikatów pominiętych</div></div>
    </div>
    """

    rows = "".join(
        f"<tr><td><a href='/sample/{u(s['sha256'])}'>{h((s.get('filename') or '')[:40])}</a></td>"
        f"<td>{h(s.get('package'))}</td>"
        f"<td class='risk-{h((s.get('ai_risk') or '').lower())}'>{h(s.get('ai_risk'))}</td>"
        f"<td>{h(s.get('vt_malicious') if s.get('vt_malicious') is not None else '')}"
        f"/{h(s.get('vt_total') if s.get('vt_total') is not None else '')}</td>"
        f"<td>{h(s.get('malware_families'))}</td>"
        f"<td>{h((s.get('first_seen') or '')[:19])}</td></tr>"
        for s in samples
    )
    samples_html = f"""
    <h1>Ostatnie próbki</h1>
    <table>
      <tr><th>Plik</th><th>Pakiet</th><th>AI risk</th><th>VT</th><th>Rodzina</th><th>Zapisano</th></tr>
      {rows or '<tr><td colspan=6>Brak danych — uruchom analyzer.py.</td></tr>'}
    </table>
    """

    reused_rows = "".join(
        f"<tr><td>{h(r['ioc_type'])}</td>"
        f"<td><a href='/search?q={u(r['value'])}'>{h(r['value'][:70])}</a></td>"
        f"<td>{h(r['sample_count'])}</td></tr>"
        for r in reused
    )
    reused_html = f"""
    <h1>Najczęściej powtarzające się IOC</h1>
    <table>
      <tr><th>Typ</th><th>Wartość</th><th>Liczba próbek</th></tr>
      {reused_rows or '<tr><td colspan=3>Brak powtórzeń.</td></tr>'}
    </table>
    """

    return _render(stats_html + samples_html + reused_html)


@app.route("/sample/<sha256>")
def sample_detail(sha256):
    sample = threat_db.get_sample(sha256)
    if not sample:
        return _render(f"<h1>Nie znaleziono próbki {h(sha256)}</h1>"), 404

    iocs = threat_db.get_iocs_for_sample(sha256)
    ioc_rows = "".join(
        f"<tr><td>{h(i['ioc_type'])}</td><td>{h(i['value'])}</td></tr>" for i in iocs
    )

    fields_html = "".join(
        f"<tr><th>{h(k)}</th><td>{h(v)}</td></tr>"
        for k, v in sample.items()
    )

    content = f"""
    <h1>{h(sample.get('filename') or sha256)}</h1>
    <table>{fields_html}</table>
    <h1>IOC ({len(iocs)})</h1>
    <table>
      <tr><th>Typ</th><th>Wartość</th></tr>
      {ioc_rows or '<tr><td colspan=2>Brak IOC.</td></tr>'}
    </table>
    """
    return _render(content)


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    results = threat_db.search_ioc(q) if q else []

    form = f"""
    <h1>Szukaj IOC</h1>
    <form class="search" method="get" action="/search">
      <input type="text" name="q" placeholder="np. fragment domeny, adresu portfela, URL..." value="{h(q)}">
      <button type="submit">Szukaj</button>
    </form>
    """

    rows = "".join(
        f"<tr><td>{h(r['ioc_type'])}</td><td>{h(r['value'][:80])}</td>"
        f"<td><a href='/sample/{u(r['sha256'])}'>{h(r.get('filename') or r['sha256'][:16])}</a></td>"
        f"<td>{h(r.get('package'))}</td></tr>"
        for r in results
    )
    results_html = f"""
    <table>
      <tr><th>Typ</th><th>Wartość</th><th>Próbka</th><th>Pakiet</th></tr>
      {rows or ('<tr><td colspan=4>Brak wyników.</td></tr>' if q else '<tr><td colspan=4>Wpisz frazę powyżej.</td></tr>')}
    </table>
    """
    return _render(form + results_html)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
