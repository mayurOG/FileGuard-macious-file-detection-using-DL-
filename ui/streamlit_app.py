"""
Malicious PE File Detector — Advanced Streamlit UI
Author: Mayur Nhavalde

Features:
  - Single-file scan with risk gauge, threat indicators, PE feature breakdown
  - Batch scan (up to 10 files) with per-file results
  - Persistent scan history for the session
  - Export history as CSV or JSON
  - Charts: confidence distribution, risk-level pie, top PE features bar chart
  - API health-check sidebar indicator
"""

import streamlit as st
import requests
import pandas as pd
import json
import io
from datetime import datetime

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Malware Detector Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = "http://fastapi:8000"

# ── Session state init ────────────────────────────────────────────────────────
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []   # list of result dicts


# ── Helpers ───────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

RISK_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#f2d00a",
    "LOW":      "#2ca02c",
}

def risk_badge(level: str) -> str:
    colors = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "goldenrod", "LOW": "green"}
    c = colors.get(level, "grey")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{level}</span>'

def confidence_bar(conf: float, prediction: str) -> None:
    color = "#d62728" if prediction == "malicious" else "#2ca02c"
    pct   = int(conf * 100)
    st.markdown(
        f"""
        <div style="background:#e0e0e0;border-radius:8px;height:22px;width:100%">
          <div style="background:{color};width:{pct}%;height:22px;border-radius:8px;
                      display:flex;align-items:center;justify-content:center;
                      color:white;font-weight:bold;font-size:13px">
            {pct}%
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

def call_api(endpoint: str, files_payload) -> dict:
    try:
        resp = requests.post(f"{API_BASE}{endpoint}", files=files_payload, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot reach the API server. Is it running?"}
    except requests.exceptions.Timeout:
        return {"error": "API request timed out after 60 s."}
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        return {"error": f"API error {e.response.status_code}: {detail}"}
    except Exception as e:
        return {"error": str(e)}

def render_result_card(result: dict) -> None:
    """Render a single scan result in an expander card."""
    pred  = result.get("prediction", "unknown")
    conf  = result.get("confidence", 0.0)
    risk  = result.get("risk_level", "—")
    fname = result.get("filename", "unknown")

    icon = "🚨" if pred == "malicious" else "✅"
    with st.expander(f"{icon}  {fname}  —  {pred.upper()}  ({conf*100:.1f}%)", expanded=True):
        col1, col2, col3 = st.columns([2, 2, 2])
        with col1:
            st.markdown(f"**Verdict:** {icon} `{pred.upper()}`")
            st.markdown(f"**Risk Level:** {risk_badge(risk)}", unsafe_allow_html=True)
        with col2:
            st.markdown(f"**Confidence Score**")
            confidence_bar(conf, pred)
        with col3:
            st.markdown(f"**SHA-256**")
            sha = result.get("sha256", "N/A")
            st.code(sha[:20] + "..." if len(sha) > 20 else sha, language=None)
            st.caption(f"⏱ Scan time: {result.get('time_taken_sec','?')} s")

        # Threat indicators
        indicators = result.get("threat_indicators", [])
        if indicators:
            st.markdown("---")
            st.markdown("##### 🔍 Threat Indicators")
            for ind in indicators:
                sev = ind.get("severity", "INFO")
                em  = SEVERITY_COLORS.get(sev, "⚪")
                st.markdown(
                    f"{em} **{ind['name']}** `[{sev}]`  \n"
                    f"{ind['description']}  \n"
                    f"*MITRE: {ind.get('mitre','N/A')}*"
                )

        # PE features breakdown
        pe_feats = result.get("pe_features", {})
        if pe_feats:
            st.markdown("---")
            st.markdown("##### 📊 PE Feature Breakdown")
            tab1, tab2 = st.tabs(["Key Metrics", "Full Feature Table"])
            with tab1:
                key_metrics = {
                    "SectionsNb":           pe_feats.get("SectionsNb"),
                    "SectionsMeanEntropy":  pe_feats.get("SectionsMeanEntropy"),
                    "SectionsMaxEntropy":   pe_feats.get("SectionsMaxEntropy"),
                    "ImportsNb":            pe_feats.get("ImportsNb"),
                    "ImportsNbDLL":         pe_feats.get("ImportsNbDLL"),
                    "ExportNb":             pe_feats.get("ExportNb"),
                    "ResourcesNb":          pe_feats.get("ResourcesNb"),
                    "CheckSum":             pe_feats.get("CheckSum"),
                    "VersionInformationSize": pe_feats.get("VersionInformationSize"),
                }
                metric_df = pd.DataFrame(
                    list(key_metrics.items()), columns=["Feature", "Value"]
                )
                c1, c2 = st.columns([2, 3])
                with c1:
                    st.dataframe(metric_df, use_container_width=True, hide_index=True)
                with c2:
                    chart_data = metric_df.set_index("Feature")
                    st.bar_chart(chart_data)
            with tab2:
                full_df = pd.DataFrame(
                    list(pe_feats.items()), columns=["Feature", "Value"]
                )
                st.dataframe(full_df, use_container_width=True, hide_index=True)


def add_to_history(result: dict) -> None:
    entry = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename":    result.get("filename", "unknown"),
        "prediction":  result.get("prediction", "unknown"),
        "confidence":  result.get("confidence", 0.0),
        "risk_level":  result.get("risk_level", "—"),
        "sha256":      result.get("sha256", ""),
        "time_sec":    result.get("time_taken_sec", 0),
    }
    st.session_state.scan_history.insert(0, entry)


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image(
        "https://img.icons8.com/color/96/000000/antivirus.png",
        width=64,
    )
    st.title("🛡️ Malware Detector Pro")
    st.caption("Deep-Learning PE File Analysis")
    st.markdown("---")

    # API health check
    st.markdown("#### API Status")
    try:
        health = requests.get(f"{API_BASE}/health", timeout=5).json()
        st.success(f"✅ Online — `{health.get('status','ok')}`")
    except Exception:
        st.error("❌ API Unreachable")

    st.markdown("---")
    st.markdown("#### About")
    st.markdown(
        "Analyses PE (`.exe`) files using a two-stage deep learning pipeline:\n"
        "1. **Autoencoder** for feature compression\n"
        "2. **ANN classifier** for prediction\n\n"
        "Built with FastAPI + Streamlit + TensorFlow."
    )
    st.markdown("---")
    st.caption("Author: **Mayur Nhavalde**")


# ── Main tabs ─────────────────────────────────────────────────────────────────
st.markdown(
    "<h1 style='text-align:center'>🛡️ Malicious PE File Detector</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align:center;color:grey'>Upload Windows PE executables for deep-learning-based malware analysis</p>",
    unsafe_allow_html=True,
)
st.markdown("---")

tab_single, tab_batch, tab_history, tab_analytics = st.tabs(
    ["🔍 Single Scan", "📦 Batch Scan", "📋 Scan History", "📈 Analytics"]
)


# ── Tab 1 · Single scan ───────────────────────────────────────────────────────
with tab_single:
    st.markdown("### Upload a single `.exe` file for analysis")
    uploaded = st.file_uploader(
        "Choose a .exe file", type=["exe"], key="single_upload"
    )

    if uploaded:
        st.info(f"📄 Selected: `{uploaded.name}`  ({uploaded.size / 1024:.1f} KB)")

        if st.button("🔍 Scan File", use_container_width=True, key="btn_single"):
            with st.spinner("Analysing… this may take a few seconds"):
                file_bytes = uploaded.read()
                payload    = {"file": (uploaded.name, file_bytes, "application/octet-stream")}
                result     = call_api("/predict", payload)

            if "error" in result:
                st.error(f"❌ {result['error']}")
            else:
                add_to_history(result)
                render_result_card(result)


# ── Tab 2 · Batch scan ────────────────────────────────────────────────────────
with tab_batch:
    st.markdown("### Upload up to **10** `.exe` files for simultaneous scanning")
    batch_files = st.file_uploader(
        "Choose .exe files", type=["exe"], accept_multiple_files=True, key="batch_upload"
    )

    if batch_files:
        st.info(f"📦 {len(batch_files)} file(s) selected.")
        if len(batch_files) > 10:
            st.warning("⚠️ Maximum 10 files — only the first 10 will be scanned.")
            batch_files = batch_files[:10]

        if st.button("🚀 Scan All Files", use_container_width=True, key="btn_batch"):
            with st.spinner(f"Scanning {len(batch_files)} file(s)…"):
                payload = [
                    ("files", (f.name, f.read(), "application/octet-stream"))
                    for f in batch_files
                ]
                result = call_api("/predict/batch", payload)

            if "error" in result:
                st.error(f"❌ {result['error']}")
            else:
                results_list = result.get("results", [])
                total   = result.get("total", len(results_list))
                mal     = sum(1 for r in results_list if r.get("prediction") == "malicious")
                legit   = total - mal

                # Summary metrics
                m1, m2, m3 = st.columns(3)
                m1.metric("Total Scanned", total)
                m2.metric("🚨 Malicious", mal)
                m3.metric("✅ Legitimate", legit)
                st.markdown("---")

                for r in results_list:
                    if "error" in r:
                        st.warning(f"⚠️ {r.get('filename','?')}: {r['error']}")
                    else:
                        add_to_history(r)
                        render_result_card(r)


# ── Tab 3 · Scan history ──────────────────────────────────────────────────────
with tab_history:
    st.markdown("### 📋 Scan History (this session)")

    if not st.session_state.scan_history:
        st.info("No scans yet. Run a scan to see results here.")
    else:
        history_df = pd.DataFrame(st.session_state.scan_history)

        # Summary bar
        total_h = len(history_df)
        mal_h   = (history_df["prediction"] == "malicious").sum()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Scans",    total_h)
        c2.metric("🚨 Malicious",   int(mal_h))
        c3.metric("✅ Legitimate",  int(total_h - mal_h))
        c4.metric("Avg Confidence", f"{history_df['confidence'].mean():.2%}")
        st.markdown("---")

        # Table with colour coding
        def color_prediction(val):
            return "color: #d62728; font-weight:bold" if val == "malicious" \
                   else "color: #2ca02c; font-weight:bold"

        st.dataframe(
            history_df.style.applymap(color_prediction, subset=["prediction"]),
            use_container_width=True,
            hide_index=True,
        )

        # Export buttons
        st.markdown("#### Export")
        ec1, ec2, _ = st.columns([1, 1, 4])
        with ec1:
            csv_buf = io.StringIO()
            history_df.to_csv(csv_buf, index=False)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv_buf.getvalue(),
                file_name="scan_history.csv",
                mime="text/csv",
            )
        with ec2:
            st.download_button(
                label="⬇️ Download JSON",
                data=json.dumps(st.session_state.scan_history, indent=2),
                file_name="scan_history.json",
                mime="application/json",
            )

        if st.button("🗑️ Clear History"):
            st.session_state.scan_history = []
            st.rerun()


# ── Tab 4 · Analytics ─────────────────────────────────────────────────────────
with tab_analytics:
    st.markdown("### 📈 Analytics Dashboard")

    if not st.session_state.scan_history:
        st.info("Run some scans first to see analytics here.")
    else:
        df = pd.DataFrame(st.session_state.scan_history)

        row1_c1, row1_c2 = st.columns(2)

        # Confidence distribution
        with row1_c1:
            st.markdown("#### Confidence Score Distribution")
            hist_df = pd.DataFrame({"Confidence": df["confidence"]})
            st.bar_chart(hist_df.assign(
                Bucket=pd.cut(hist_df["Confidence"], bins=10)
            ).groupby("Bucket", observed=True).size().rename("Count"))

        # Risk level pie (using bar chart as Streamlit has no native pie)
        with row1_c2:
            st.markdown("#### Risk Level Breakdown")
            risk_counts = df["risk_level"].value_counts().rename_axis("Risk").reset_index(name="Count")
            st.bar_chart(risk_counts.set_index("Risk"))

        # Malicious vs legitimate over time
        st.markdown("#### Malicious vs Legitimate Over Time")
        df["is_malicious"] = (df["prediction"] == "malicious").astype(int)
        df_time = df[["timestamp", "is_malicious"]].copy()
        df_time.index = range(len(df_time))
        st.line_chart(df_time.set_index("timestamp")["is_malicious"])

        # Recent scans table
        st.markdown("#### Recent 10 Scans")
        st.dataframe(df.head(10), use_container_width=True, hide_index=True)
