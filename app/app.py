from flask import Flask, request, render_template_string
import pandas as pd
import numpy as np
import pickle, json, os
from io import StringIO

from tensorflow import keras

app = Flask(__name__)

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model")

# تحميل النماذج والإعدادات مرة واحدة عند تشغيل التطبيق
def load_models():
    cfg_path = os.path.join(MODEL_DIR, "config.json")
    if not os.path.exists(cfg_path):
        return None, None, None, None, [], []
    with open(cfg_path) as f:
        config = json.load(f)
    ae   = keras.models.load_model(os.path.join(MODEL_DIR, "autoencoder.h5"),      compile=False)
    lstm = keras.models.load_model(os.path.join(MODEL_DIR, "lstm_autoencoder.h5"), compile=False)
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    dept_classes = []
    role_classes = []
    enc_path = os.path.join(MODEL_DIR, "context_encoders.pkl")
    if os.path.exists(enc_path):
        with open(enc_path, "rb") as f:
            ctx = pickle.load(f)
        if "dept_encoder" in ctx:
            dept_classes = list(ctx["dept_encoder"].classes_)
        if "role_encoder" in ctx:
            role_classes = list(ctx["role_encoder"].classes_)
    return config, ae, lstm, scaler, dept_classes, role_classes

config, ae_model, lstm_model, scaler, dept_classes, role_classes = load_models()

# قالب صفحة لوحة التحكم
PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Insider Threat Detector</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.28/jspdf.plugin.autotable.min.js"></script>
</head>
<body>

<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">�</div>
    <div class="logo-text"><div class="lt">Insider Threat</div><div class="ls">Detection System</div></div>
  </div>
  <a class="nav-item active" href="#"><span class="nav-icon">📊</span> Dashboard</a>
</aside>

<div class="main">
  <div class="topbar">
    <h1>Dashboard</h1>
    <div class="topbar-right">
      {% if results %}
      <button class="btn btn-sm btn-green" onclick="exportCSV()">⬇ Export CSV</button>
      <button class="btn btn-sm btn-orange" onclick="exportPDF()">⬇ Download PDF Report</button>
      {% endif %}
    </div>
  </div>

{% if not model_ready %}
  <div class="card"><p class="error">⚠️ Model files not found in <code>model/</code>. Train the model first.</p></div>
{% else %}

<div class="card">
  <form method="post" enctype="multipart/form-data">
    <label><b>Upload Employee Activity CSV</b></label><br>
    <input type="file" name="csv_file" accept=".csv" required>
    <br>
    <button class="btn" type="submit">▶ Run Detection</button>
  </form>
  {% if error %}<p class="error">{{ error }}</p>{% endif %}
</div>

{% if results %}

<div class="stats">
  <div class="stat">
    <div class="stat-icon i-total">👥</div>
    <div><div class="stat-num c-total">{{ stats.total }}</div><div class="stat-lbl">Total Employees</div></div>
  </div>
  <div class="stat">
    <div class="stat-icon i-high">🔴</div>
    <div><div class="stat-num c-high">{{ stats.high }}</div><div class="stat-lbl">High Risk</div></div>
  </div>
  <div class="stat">
    <div class="stat-icon i-medium">🟡</div>
    <div><div class="stat-num c-medium">{{ stats.medium }}</div><div class="stat-lbl">Medium Risk</div></div>
  </div>
  <div class="stat">
    <div class="stat-icon i-low">🟢</div>
    <div><div class="stat-num c-low">{{ stats.low }}</div><div class="stat-lbl">Normal</div></div>
  </div>
</div>

<div class="charts-row">
  <div class="chart-card">
    <div class="chart-title">Risk Level Distribution</div>
    <div class="chart-box"><canvas id="donutChart"></canvas></div>
  </div>
  <div class="chart-card">
    <div class="chart-title">Top Employees — Threat Score</div>
    <div class="chart-box"><canvas id="barChart"></canvas></div>
  </div>
  <div class="chart-card wide">
    <div class="chart-title">Average Anomaly Trend (All Employees)</div>
    <div class="chart-box"><canvas id="trendChart"></canvas></div>
  </div>
</div>

<div class="legend">
  <span><span class="dot" style="background:#e53935"></span> Above 60% = High Risk</span>
  <span><span class="dot" style="background:#fb8c00"></span> 30%–60% = Medium Risk</span>
  <span><span class="dot" style="background:#43a047"></span> Below 30% = Normal</span>
</div>

<div class="table-card">
  <div class="table-header">
    <h3>Employee Risk Analysis</h3>
  </div>
  <table id="mainTable">
    <thead>
      <tr>
        <th>Employee<span class="th-sub">Account name</span></th>
        <th>Department<span class="th-sub">Division</span></th>
        <th>Role<span class="th-sub">Job title</span></th>
        <th>
          <span class="tip" title="Probability of being a threat — 0% = normal, 100% = very dangerous">Threat Score</span>
          <span class="th-sub">0% = Normal ← 100% = Danger</span>
        </th>
        <th>
          <span class="tip" title="Is the employee's behavior on a single day unusual? High = abnormal day">Daily Anomaly</span>
          <span class="th-sub">Current day vs. baseline</span>
        </th>
        <th>
          <span class="tip" title="Has behavior shifted across consecutive periods? High = persistent change">Sequential Anomaly</span>
          <span class="th-sub">Pattern change over time</span>
        </th>
        <th>
          <span class="tip" title="After-hours logins, USB activity and other suspicious signals">Suspicious Behavior</span>
          <span class="th-sub">After-hours + USB + context</span>
        </th>
        <th>Risk Level<span class="th-sub">Assessment</span></th>
        <th>Recommended Action<span class="th-sub">Next steps</span></th>
      </tr>
    </thead>
    <tbody>
      {% for r in results %}
      <tr onclick="showUser('{{ r.user }}')" title="Click to view details">
        <td><b>{{ r.user }}</b></td>
        <td style="font-size:0.85em;">{{ r.department }}</td>
        <td style="font-size:0.85em;color:var(--muted)">{{ r.role }}</td>
        <td>
          <div class="bar-wrap"><div class="bar-fill bar-{{ r.level_class }}" style="width:{{ r.risk_pct }}"></div></div>
          <span class="pct-label" style="color:{{ r.risk_color }}">{{ r.risk_pct }}</span>
        </td>
        <td>
          <div class="bar-wrap"><div class="bar-fill bar-neutral" style="width:{{ r.ae_pct }}"></div></div>
          <span style="font-size:0.85em;color:var(--muted)">{{ r.ae_pct }}</span>
        </td>
        <td>
          <div class="bar-wrap"><div class="bar-fill bar-neutral" style="width:{{ r.lstm_pct }}"></div></div>
          <span style="font-size:0.85em;color:var(--muted)">{{ r.lstm_pct }}</span>
        </td>
        <td>
          <div class="bar-wrap"><div class="bar-fill bar-neutral" style="width:{{ r.ctx_pct }}"></div></div>
          <span style="font-size:0.85em;color:var(--muted)">{{ r.ctx_pct }}</span>
        </td>
        <td><span class="badge badge-{{ r.level_class }}">{{ r.level }}</span></td>
        <td class="action-{{ r.level_class }}">{{ r.action }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
  <div class="modal" id="modalBox">
    <button class="modal-close" onclick="closeModalDirect()" title="Close">&times;</button>

    <h2 id="mUser">👤 —</h2>
    <div class="m-sub" id="mSub">—</div>

    <div class="kpi-row">
      <div class="kpi"><div class="kv" id="mRisk">—</div><div class="kl">Threat Score</div></div>
      <div class="kpi"><div class="kv" id="mDays">—</div><div class="kl">Periods Monitored</div></div>
      <div class="kpi"><div class="kv" id="mLogons">—</div><div class="kl">Total Logons</div></div>
      <div class="kpi"><div class="kv" id="mAH">—</div><div class="kl">After-Hours Logons</div></div>
      <div class="kpi"><div class="kv" id="mUSB">—</div><div class="kl">USB Connections</div></div>
    </div>

    <p class="section-title">Individual Activity Timeline</p>
    <div class="chart-legend">
      <span><span class="cl-dot" style="background:#e53935"></span> Daily Anomaly (AE)</span>
      <span><span class="cl-dot" style="background:#4f80ff"></span> Sequential Anomaly (LSTM)</span>
    </div>
    <div class="chart-wrap">
      <canvas id="timelineChart"></canvas>
    </div>
    <p style="font-size:0.75em;color:var(--muted);margin:4px 0 22px;">
      Each point = one monitoring period in the CSV. Higher value = more unusual behavior.
    </p>

    <p class="section-title">Daily Activity Log</p>
    <div class="act-wrap">
      <table class="act-table">
        <thead><tr>
          <th>Date</th><th>Logons</th><th>After-Hours</th><th>Weekend</th>
          <th>USB</th><th>USB Night</th><th>Files</th><th>Ext. Transfer</th>
          <th>HTTP Req.</th><th>Domains</th><th>Anomaly</th>
        </tr></thead>
        <tbody id="actBody"></tbody>
      </table>
    </div>

    <p class="section-title">Score Breakdown</p>
    <table class="breakdown-table">
      <thead><tr><th>Indicator</th><th>Score</th><th>Description</th></tr></thead>
      <tbody>
        <tr>
          <td>Daily Anomaly (AE)</td><td id="mbAE">—</td>
          <td style="color:var(--muted);font-size:0.9em;">Single-period behavior vs. baseline</td>
        </tr>
        <tr>
          <td>Sequential Anomaly (LSTM)</td><td id="mbLSTM">—</td>
          <td style="color:var(--muted);font-size:0.9em;">Pattern deviation across consecutive periods</td>
        </tr>
        <tr>
          <td>Suspicious Behavior</td><td id="mbCTX">—</td>
          <td style="color:var(--muted);font-size:0.9em;">After-hours logins + USB + contextual signals</td>
        </tr>
        <tr>
          <td><b>Overall Threat Score</b></td><td id="mbRISK">—</td>
          <td style="color:var(--muted);font-size:0.9em;">Weighted combination of all signals above</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

{% endif %}
{% endif %}
</div>

<script>
window.allResults = {{ results_json | safe }};
</script>
<script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>

</body>
</html>
"""

def _decode(classes, encoded_val):
    # يحوّل الرقم المخزن في CSV إلى اسم القسم أو الدور الحقيقي من ملفات التدريب
    try:
        idx = int(round(float(encoded_val)))
        if 0 <= idx < len(classes):
            return classes[idx]
    except Exception:
        pass
    return "Unknown"


def run_detection(df):
    # يطبّق نفس ترتيب الخصائص المستخدم أثناء التدريب حتى تكون نتائج النموذج صحيحة
    FEAT_COLS = config["feature_columns"]
    SEQ_LEN   = config["sequence_length"]
    W         = config["risk_weights"]

    for col in FEAT_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    X      = scaler.transform(df[FEAT_COLS].values)
    X_pred = ae_model.predict(X, verbose=0)
    ae_err = np.mean((X - X_pred) ** 2, axis=1)
    ae_n   = (ae_err - ae_err.min()) / (ae_err.max() - ae_err.min() + 1e-10)
    df["_ae"] = ae_n

    rows = []
    for user in df["user"].unique():
        ud     = df[df["user"] == user].reset_index(drop=True)
        ae_max = float(ud["_ae"].max())
        ae_avg = float(ud["_ae"].mean())

        u_X         = scaler.transform(ud[FEAT_COLS].values)
        lstm_max    = 0.0
        lstm_scores = []
        if len(u_X) >= SEQ_LEN:
            seqs  = np.array([u_X[i:i + SEQ_LEN] for i in range(len(u_X) - SEQ_LEN + 1)])
            sp    = lstm_model.predict(seqs, verbose=0)
            err   = np.mean((seqs - sp) ** 2, axis=(1, 2))
            err_n = (err - err.min()) / (err.max() - err.min() + 1e-10)
            lstm_max    = float(err_n.max())
            lstm_scores = err_n.tolist()

        logons = max(int(ud["logon_count"].sum()), 1)
        ah     = int(ud["after_hours_logon"].sum()) if "after_hours_logon" in ud.columns else 0
        usb    = int(ud["usb_connect_count"].sum()) if "usb_connect_count" in ud.columns else 0
        ctx    = min(1.0, (ah / logons) * 0.5 + min(usb / 50, 0.5))

        department = _decode(dept_classes, ud["dept_encoded"].iloc[0]) if "dept_encoded" in ud.columns else "Unknown"
        role       = _decode(role_classes, ud["role_encoded"].iloc[0]) if "role_encoded" in ud.columns else "Unknown"

        risk = min(1.0, W["ae_max"] * ae_max + W["lstm_max"] * lstm_max +
                        W["ae_avg"] * ae_avg + W["context"] * ctx)

        level = "HIGH" if risk > 0.6 else ("MEDIUM" if risk > 0.3 else "LOW")
        level_en = {"HIGH": "High Risk", "MEDIUM": "Medium Risk", "LOW": "Normal"}
        color    = {"HIGH": "#e53935",   "MEDIUM": "#fb8c00",      "LOW": "#43a047"}
        action   = {
            "HIGH":   "Immediate manual review — contact supervisor",
            "MEDIUM": "Monitor account and verify later",
            "LOW":    "No action required",
        }

        # يحوّل الدرجة العشرية إلى نسبة مئوية مختصرة للعرض في الواجهة
        def pct(val):
            return f"{min(val*100, 100):.0f}%"

        # تجهيز بيانات الخط الزمني لكل موظف لعرضها داخل النافذة التفصيلية
        has_date      = "date" in ud.columns
        day_col       = "date" if has_date else ("day" if "day" in ud.columns else None)
        timeline_lbls = ud[day_col].astype(str).tolist() if day_col else [f"Period {i+1}" for i in range(len(ud))]
        ae_timeline   = [round(float(v) * 100, 1) for v in ud["_ae"].tolist()]
        lstm_timeline = [0.0] * len(ud)
        for i, v in enumerate(lstm_scores):
            if i < len(ud):
                lstm_timeline[i] = round(float(v) * 100, 1)

        # تجهيز سجل النشاط اليومي للموظف حتى تظهر التفاصيل في الجدول الداخلي
        def _icol(col, row_idx, default=0):
            return int(ud[col].iloc[row_idx]) if col in ud.columns else default

        activity_log = []
        for idx in range(len(ud)):
            activity_log.append({
                "day":          timeline_lbls[idx],
                "logons":       _icol("logon_count", idx),
                "after_hours":  _icol("after_hours_logon", idx),
                "weekend":      _icol("weekend_logon", idx),
                "usb":          _icol("usb_connect_count", idx),
                "usb_ah":       _icol("usb_after_hours", idx),
                "files":        _icol("file_action_count", idx),
                "files_ext":    _icol("file_to_removable", idx),
                "http":         _icol("http_count", idx),
                "domains":      _icol("unique_domains", idx),
                "anomaly":      ae_timeline[idx],
            })

        rows.append({
            "user":           user,
            "risk":           risk,
            "risk_pct":       pct(risk),
            "risk_color":     color[level],
            "ae_pct":         pct(ae_max),
            "lstm_pct":       pct(lstm_max),
            "ctx_pct":        pct(ctx),
            "level":          level_en[level],
            "level_class":    level.lower(),
            "action":         action[level],
            # بيانات مختصرة تظهر داخل نافذة تفاصيل الموظف
            "total_logons":   logons,
            "after_hours":    ah,
            "usb_count":      usb,
            "days_monitored": len(ud),
            # بيانات الرسوم الخاصة بالموظف
            "timeline_labels": timeline_lbls,
            "ae_timeline":     ae_timeline,
            "lstm_timeline":   lstm_timeline,
            # سجل النشاط اليومي
            "activity_log":   activity_log,
            # معلومات السياق القادمة من LDAP بعد فك الترميز
            "department":     department,
            "role":           role,
        })

    return sorted(rows, key=lambda r: r["risk"], reverse=True)


@app.route("/", methods=["GET", "POST"])
def index():
    # يستقبل ملف CSV من المستخدم، يتحقق من الأعمدة المطلوبة، ثم يعرض نتائج الكشف
    model_ready = config is not None
    error        = None
    results      = None
    results_json = "[]"
    stats        = None

    if request.method == "POST" and model_ready:
        f = request.files.get("csv_file")
        if not f:
            error = "No file uploaded."
        else:
            try:
                df = pd.read_csv(StringIO(f.read().decode("utf-8")))
                FEAT_COLS = config["feature_columns"]
                missing = [c for c in FEAT_COLS if c not in df.columns]
                if "user" not in df.columns:
                    error = "CSV must have a 'user' column."
                elif missing:
                    error = f"Missing columns: {missing}"
                else:
                    results      = run_detection(df)
                    results_json = json.dumps(results, ensure_ascii=False)
                    stats = {
                        "total":  len(results),
                        "high":   sum(1 for r in results if r["level_class"] == "high"),
                        "medium": sum(1 for r in results if r["level_class"] == "medium"),
                        "low":    sum(1 for r in results if r["level_class"] == "low"),
                    }
            except Exception as e:
                error = f"Error processing file: {e}"

    return render_template_string(PAGE, model_ready=model_ready, error=error,
                                  results=results, results_json=results_json, stats=stats)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

