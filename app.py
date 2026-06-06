"""Optional web UI for the Phishing Triage CLI.

A thin Flask front-end over the existing engine: it parses the pasted email and
calls the SAME build_report() the CLI uses. Run it with:

    python app.py

then open http://127.0.0.1:5000 in your browser.

Pick a background style with ?bg=1 .. ?bg=5 (or the switcher bar in the header).
"""

from pathlib import Path

from flask import Flask, request, render_template_string

from phishing_triage.parser import parse_bytes
from phishing_triage.iocs import defang
from phishing_triage.cli import build_report

app = Flask(__name__)

# Pre-fill the form with our sample email so the page is usable immediately.
SAMPLE = Path(__file__).resolve().parent / "samples" / "phishing_sample.eml"
SAMPLE_TEXT = SAMPLE.read_text(encoding="utf-8") if SAMPLE.exists() else ""

VERDICT_COLORS = {"High": "#ff2e63", "Medium": "#ffb302", "Low": "#39ff14"}

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>PHISH//TRIAGE</title>
  <style>
    :root { --cyan: #22d3ee; --green: #34d399; --red: #fb5779; --amber: #fbbf24;
            --violet: #a78bfa; --ink: #e6f2f7;
            --panel: rgba(16,24,46,.62); --line: rgba(120,170,255,.18);
            color-scheme: dark; }
    /* The gradient lives on the ROOT element so it fills the entire canvas,
       including behind the scrollbar gutter — otherwise a body background gets
       clipped there and leaves a seam strip down the right edge. The dark base
       colour also prevents a white flash during page reloads. */
    html, body { overflow-x: hidden; }
    html {
      background: radial-gradient(circle at 50% -10%, #11193a, #070b1c) no-repeat fixed;
      background-color: #070b1c;
    }
    * { box-sizing: border-box; }
    body {
      font-family: 'Inter','Segoe UI',system-ui,sans-serif;
      color: var(--ink); margin: 0; min-height: 100vh; padding: 2.6rem 1rem;
      /* transparent so the root gradient shows through with no seam */
      background: transparent;
    }
    /* Starfield Drift: two parallax star layers slowly rising */
    body::before { content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
      background-image:
        radial-gradient(1px 1px at 20px 30px, rgba(180,220,255,.5), transparent),
        radial-gradient(1px 1px at 80px 120px, rgba(170,210,255,.4), transparent),
        radial-gradient(1.5px 1.5px at 150px 70px, rgba(160,200,255,.5), transparent),
        radial-gradient(1px 1px at 210px 160px, rgba(200,225,255,.4), transparent);
      background-size:240px 240px; animation: stars-far 90s linear infinite; }
    @keyframes stars-far { to { background-position: 0 -2400px; } }
    body::after { content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
      background-image:
        radial-gradient(1.5px 1.5px at 40px 50px, rgba(120,230,255,.55), transparent),
        radial-gradient(2px 2px at 160px 150px, rgba(150,255,230,.45), transparent);
      background-size:320px 320px; animation: stars-near 50s linear infinite; }
    @keyframes stars-near { to { background-position: 0 -3200px; } }
    @media (prefers-reduced-motion: reduce) {
      body, body::before, body::after { animation: none !important; }
    }
    .wrap { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; }

    /* header */
    .top { display: flex; align-items: center; justify-content: space-between;
           gap: 1rem; flex-wrap: wrap; padding-bottom: 1rem;
           border-bottom: 1px solid var(--line); }
    .brand { display: flex; align-items: center; gap: .7rem; }
    .logo { width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center;
            font-size: 20px; background: linear-gradient(145deg, #1b2750, #0e1633);
            border: 1px solid rgba(120,170,255,.3);
            box-shadow: 0 6px 18px rgba(0,0,0,.35), inset 0 0 14px rgba(34,211,238,.12); }
    h1 { font-size: 1.45rem; font-weight: 700; letter-spacing: .5px; margin: 0; line-height: 1;
         background: linear-gradient(90deg, #7ee8fa, #a78bfa);
         -webkit-background-clip: text; background-clip: text; color: transparent; }
    h1 small { display: block; font-size: .62rem; letter-spacing: 3px; font-weight: 600;
               color: #7f9bc4; margin-top: .35rem; -webkit-text-fill-color: #7f9bc4; }
    .tag { font-size: .66rem; font-weight: 600; letter-spacing: 2px; color: var(--green);
           background: rgba(52,211,153,.08); border: 1px solid rgba(52,211,153,.35);
           padding: .32rem .7rem; border-radius: 999px; }
    .tag .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%;
                background: var(--green); margin-right: .45rem; box-shadow: 0 0 8px var(--green);
                animation: pulse 1.6s ease-in-out infinite; vertical-align: middle; }
    @keyframes pulse { 50% { opacity: .35; } }
    .sub { color: #8aa6c7; font-size: .85rem; letter-spacing: .3px; margin: 1.1rem 0 .8rem; }
    .blink { animation: blink 1.1s steps(2) infinite; color: var(--cyan); }
    @keyframes blink { 50% { opacity: 0; } }

    .panel { background: var(--panel); border: 1px solid var(--line);
             border-radius: 14px; padding: 1.2rem 1.3rem; backdrop-filter: blur(10px);
             box-shadow: 0 10px 40px rgba(4,8,20,.45); }
    label.fld { display: block; font-size: .68rem; letter-spacing: 2px; color: #8fb2d8;
                margin-bottom: .5rem; text-transform: uppercase; font-weight: 600; }
    textarea { width: 100%; height: 230px; resize: vertical; color: #c8f3da;
               background: rgba(4,9,20,.72); border: 1px solid var(--line); border-radius: 10px;
               font-family: 'Consolas','Courier New',monospace; font-size: 12.5px;
               padding: .8rem; line-height: 1.5; }
    textarea:focus { outline: none; border-color: var(--cyan);
                     box-shadow: 0 0 0 3px rgba(34,211,238,.18); }
    .controls { margin-top: 1rem; display: flex; align-items: center;
                justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
    .hint { font-size: .76rem; color: #8aa6c7; line-height: 1.55; margin: .6rem 0 0;
            padding: .6rem .75rem; border-left: 2px solid var(--line);
            background: rgba(8,14,30,.4); border-radius: 0 6px 6px 0; }
    .hint b { color: #9fd9e3; font-weight: 600; }
    .chk { font-size: .8rem; color: #9fbdd8; letter-spacing: .2px; }
    .chk input { accent-color: var(--cyan); margin-right: .45rem; transform: translateY(1px); }
    button { font-family: inherit; font-weight: 600; font-size: .9rem; letter-spacing: .4px;
             cursor: pointer; color: #07101f;
             background: linear-gradient(135deg, #7ee8fa 0%, #34d399 100%);
             border: 0; padding: .7rem 1.7rem; border-radius: 10px;
             box-shadow: 0 8px 22px rgba(34,211,238,.28); transition: transform .1s, box-shadow .2s, filter .2s; }
    button:hover { filter: brightness(1.07); box-shadow: 0 10px 28px rgba(34,211,238,.45);
                   transform: translateY(-1px); }
    button:active { transform: translateY(0); }

    .result { margin-top: 1.4rem; }
    .verdict-row { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    .badge { font-weight: 800; letter-spacing: 2px; text-transform: uppercase;
             padding: .45rem 1.1rem; border-radius: 4px; color: #02060d;
             border: 1px solid currentColor; }
    .score { font-size: 2rem; font-weight: 800; }
    .meta { color: #8fb6c0; font-size: .82rem; margin: .9rem 0 0; line-height: 1.6; }
    .meta b { color: var(--cyan); letter-spacing: 1px; }
    h3 { color: var(--cyan); font-size: .8rem; letter-spacing: 3px; text-transform: uppercase;
         border-bottom: 1px dashed var(--line); padding-bottom: .35rem; margin: 1.3rem 0 .7rem; }
    h3::before { content: "▸ "; color: var(--green); }
    .sig { margin: .35rem 0; font-size: .86rem; color: #d4eef3; }
    .w { display: inline-block; min-width: 2.6rem; font-weight: 800; color: var(--red);
         text-shadow: 0 0 8px rgba(255,46,99,.6); }
    .ioc { font-size: .85rem; color: var(--amber); padding: .15rem 0; }
    .ioc .k { color: var(--cyan); margin-right: .5rem; }
    .act { font-size: .86rem; color: #d4eef3; padding: .2rem 0 .2rem 1.1rem; position: relative; }
    .act::before { content: ">"; position: absolute; left: 0; color: var(--green); }
    .empty { color: #6fb9c7; font-size: .85rem; }
    .foot { margin-top: 1.6rem; text-align: center; color: #466; font-size: .7rem; letter-spacing: 2px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <div class="logo">🛡️</div>
        <h1>PHISH//TRIAGE<small>SOC ANALYST CONSOLE</small></h1>
      </div>
      <span class="tag"><span class="dot"></span>ANALYSIS NODE · ONLINE</span>
    </div>
    <p class="sub">Paste a raw .eml payload and run threat analysis<span class="blink"> _</span></p>

    <form method="post">
      <div class="panel">
        <label class="fld">&gt; paste raw email source</label>
        <textarea name="eml" spellcheck="false">{{ eml_text }}</textarea>
        <p class="hint">No file needed — paste the email's <b>raw source</b> (it includes the
          headers we analyze). To get it:<br>
          &nbsp;&bull; <b>Gmail:</b> open the email → &#8942; menu → <b>Show original</b> → Copy to clipboard → paste here.<br>
          &nbsp;&bull; <b>Outlook (web):</b> open the email → &#8942; → <b>View message source</b> → select all → paste here.<br>
          &nbsp;&bull; <b>Apple Mail:</b> select the email → menu <b>View → Message → Raw Source</b> → copy → paste here.</p>
        <div class="controls">
          <span class="chk"><label><input type="checkbox" name="enrich" {% if enrich %}checked{% endif %}>
            enrich IOCs via VirusTotal / AbuseIPDB &nbsp;[live · uses API quota]</label></span>
          <button type="submit">▶ Analyze</button>
        </div>
      </div>
    </form>

    {% if report %}
    <div class="result panel" style="border-color: {{ color }}; box-shadow: 0 0 28px {{ color }}33;">
      <div class="verdict-row">
        <span class="badge" style="background: {{ color }}; color:#02060d; box-shadow: 0 0 18px {{ color }}99;">
          {{ report.assessment.verdict }} THREAT
        </span>
        <span class="score" style="color: {{ color }}; text-shadow: 0 0 14px {{ color }};">
          {{ report.assessment.score }}
        </span>
        <span class="meta" style="margin:0;">phishing likelihood score</span>
      </div>
      <p class="meta"><b>FROM</b> {{ report.sender }}<br>
         <b>SUBJ</b> {{ report.subject }}</p>

      <h3>Detection signals</h3>
      {% if report.assessment.signals %}
        {% for weight, reason in report.assessment.signals %}
          <div class="sig"><span class="w">+{{ weight }}</span> {{ reason }}</div>
        {% endfor %}
      {% else %}
        <p class="empty">No phishing indicators detected.</p>
      {% endif %}

      <h3>Indicators of compromise // defanged</h3>
      {% for u in report.iocs.urls %}<div class="ioc"><span class="k">URL</span>{{ defang(u) }}</div>{% endfor %}
      {% for ip in report.iocs.ips %}<div class="ioc"><span class="k">IP&nbsp;</span>{{ defang(ip) }}</div>{% endfor %}
      {% if not report.iocs.urls and not report.iocs.ips %}<p class="empty">None found.</p>{% endif %}

      <h3>Recommended actions</h3>
      {% for action in report.assessment.recommended_actions %}<div class="act">{{ action }}</div>{% endfor %}
    </div>
    {% endif %}

    <div class="foot">PHISH//TRIAGE · LOCAL ANALYSIS NODE · 127.0.0.1</div>
  </div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    eml_text = SAMPLE_TEXT
    enrich = True

    if request.method == "POST":
        eml_text = request.form.get("eml", "")
        enrich = request.form.get("enrich") is not None
        msg = parse_bytes(eml_text.encode("utf-8"))
        report = build_report(msg, source="(pasted email)", enrich=enrich)
    elif request.args.get("demo"):
        # Show the bundled sample report on a plain GET — handy for a quick look
        # without pasting anything. Add &live=1 to run real enrichment too.
        enrich = request.args.get("live") is not None
        msg = parse_bytes(SAMPLE_TEXT.encode("utf-8"))
        report = build_report(msg, source="samples/phishing_sample.eml", enrich=enrich)

    color = VERDICT_COLORS.get(
        report["assessment"]["verdict"] if report else "", "#566573"
    )
    return render_template_string(
        PAGE, report=report, eml_text=eml_text, enrich=enrich,
        color=color, defang=defang,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
