"""
WebScan Pro — Streamlit Dashboard
Full pipeline: UnifiedScanner (XSS+SQLi) + IDOR detection + RAG AI analysis
"""

import streamlit as st
import time
import json
import os
import sys
import re
import requests as http_requests
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ── Path setup ──────────────────────────────────────────────────────────────
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ── Optional imports (graceful degradation) ──────────────────────────────────
RAG_AVAILABLE = False
try:
    from projects.auth_session.ml.rag.rag_pipeline import generate_augmented_report
    RAG_AVAILABLE = True
except Exception:
    pass

UNIFIED_SCANNER_AVAILABLE = False
try:
    from projects.unified_scanner.unified_scanner import UnifiedScanner
    UNIFIED_SCANNER_AVAILABLE = True
except Exception:
    pass

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebScan Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

  /* Typography */
  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  h1, h2, h3 { color: var(--text-color) !important; font-family: 'Inter', sans-serif; }
  h1 { font-size: 2rem; font-weight: 700; letter-spacing: -0.5px; }

  /* Custom Metric Cards */
  .metric-card {
    background: var(--secondary-background-color);
    border: 1px solid rgba(128,128,128,0.2); 
    padding: 20px;
    border-radius: 12px; 
    text-align: center;
    transition: all 0.2s ease;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
  }
  .metric-card:hover { 
    border-color: var(--primary-color);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    transform: translateY(-2px);
  }
  .metric-value { 
    font-size: 2.2rem; 
    font-weight: 700; 
    color: var(--text-color); 
  }
  .metric-label { 
    font-size: 0.8rem; 
    color: var(--text-color);
    opacity: 0.7;
    text-transform: uppercase; 
    letter-spacing: 0.5px; 
    margin-top: 4px; 
  }
</style>
""", unsafe_allow_html=True)

# ── Session State Init ────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []


# ═══════════════════════════════════════════════════════════════════════════════
# IDOR Rule-Based Engine
# ═══════════════════════════════════════════════════════════════════════════════
IDOR_PATTERNS = [
    r"[?&](id|user_?id|account_?id|profile_?id|order_?id|doc_?id|file_?id|record_?id)=\d+",
    r"[?&](uid|pid|aid|oid|rid|fid)=\d+",
    r"/api/(users?|accounts?|profiles?|orders?|documents?)/\d+",
    r"/\d{1,10}(/|$)",
    r"[?&](uuid|guid)=[0-9a-f\-]{32,}",
]

PERSONAL_DATA_PATTERNS = [
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
    r'"(ssn|social_security|credit_card|card_number)"',
    r'"(password|passwd|secret|api_key)"',
    r'"(address|street|zip|postal)"',
]


def detect_idor_in_url(url: str):
    findings = []
    for pattern in IDOR_PATTERNS:
        m = re.search(pattern, url, re.IGNORECASE)
        if m:
            findings.append({"matched": m.group(0), "pattern": pattern})
    return findings


def probe_idor(url: str, timeout: int = 5):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    path_segments = parsed.path.split("/")

    id_params = {}
    for k, v in params.items():
        if re.match(r"(id|user_?id|uid|pid|oid|account|profile|order|file|doc|record)", k, re.I):
            try:
                id_params[k] = int(v[0])
            except (ValueError, IndexError):
                pass

    if not id_params:
        for i, seg in enumerate(path_segments):
            if seg.isdigit():
                id_params[f"__path_{i}"] = int(seg)

    if not id_params:
        return findings

    try:
        orig_resp = http_requests.get(url, timeout=timeout, allow_redirects=True)
        orig_len = len(orig_resp.text)
        orig_status = orig_resp.status_code

        for param, orig_id in id_params.items():
            adjacent_ids = [orig_id - 1, orig_id + 1, orig_id + 10, 1, 2, 100]
            for test_id in adjacent_ids:
                if test_id == orig_id or test_id <= 0:
                    continue

                if param.startswith("__path_"):
                    idx = int(param.split("_")[-1])
                    new_segs = path_segments.copy()
                    new_segs[idx] = str(test_id)
                    new_path = "/".join(new_segs)
                    test_url = urlunparse(parsed._replace(path=new_path))
                else:
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[param] = str(test_id)
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))

                try:
                    test_resp = http_requests.get(test_url, timeout=timeout, allow_redirects=True)
                    test_len = len(test_resp.text)
                    test_status = test_resp.status_code

                    is_idor = False
                    reason = ""

                    if test_status == 200 and orig_status == 200 and abs(test_len - orig_len) < orig_len * 0.2:
                        is_idor = True
                        reason = "Different user's resource returned similar-sized 200 response"

                    for pat in PERSONAL_DATA_PATTERNS:
                        if re.search(pat, test_resp.text, re.IGNORECASE):
                            is_idor = True
                            reason = "Personal/sensitive data found in cross-user response"
                            break

                    if is_idor:
                        findings.append({
                            "original_url": url,
                            "test_url": test_url,
                            "param": param,
                            "original_id": orig_id,
                            "tested_id": test_id,
                            "status": test_status,
                            "response_length": test_len,
                            "reason": reason,
                        })
                        break

                except Exception:
                    pass

    except Exception:
        pass

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Adapter
# ═══════════════════════════════════════════════════════════════════════════════
def get_scanner(use_mock: bool, timeout: int, max_payloads: int):
    config = {
        "use_mock_models": use_mock or not UNIFIED_SCANNER_AVAILABLE,
        "timeout": timeout,
        "max_payloads": max_payloads,
        "threads": 2,
    }
    if UNIFIED_SCANNER_AVAILABLE and not use_mock:
        try:
            return UnifiedScanner(config)
        except Exception:
            pass

    # Fallback scanner using mock models
    from projects.unified_scanner.mock_models import get_mock_xss_model, get_mock_sqli_model
    from projects.unified_scanner.utils import get_xss_payloads, get_sqli_payloads, make_request

    class _FallbackScanner:
        def __init__(self):
            self.xss = get_mock_xss_model()
            self.sqli = get_mock_sqli_model()

        def scan_url(self, url):
            payloads_xss = get_xss_payloads(max_payloads)
            payloads_sqli = get_sqli_payloads(max_payloads)
            result = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "xss": {"is_vulnerable": False, "probability": 0.0,
                        "payloads_tested": len(payloads_xss), "vulnerable_payloads": []},
                "sqli": {"is_vulnerable": False, "probability": 0.0,
                         "payloads_tested": len(payloads_sqli), "vulnerable_payloads": []},
            }

            max_xss_prob = 0.0
            for p in payloads_xss:
                resp = make_request(url, {"test": p}, timeout=timeout)
                if resp:
                    is_vuln, prob = self.xss.predict_xss(resp.text)
                    if prob > max_xss_prob:
                        max_xss_prob = prob
                    if is_vuln:
                        result["xss"]["vulnerable_payloads"].append({"payload": p, "probability": prob})
            result["xss"]["probability"] = max_xss_prob
            result["xss"]["is_vulnerable"] = max_xss_prob >= 0.75

            max_sqli_prob = 0.0
            for p in payloads_sqli:
                resp = make_request(url, {"test": p}, timeout=timeout)
                if resp:
                    r = self.sqli.predict({"url": url, "payload": p}, {"text": resp.text})
                    prob = r.get("probability", 0.0)
                    if prob > max_sqli_prob:
                        max_sqli_prob = prob
                    if r.get("is_malicious"):
                        result["sqli"]["vulnerable_payloads"].append({"payload": p, "probability": prob})
            result["sqli"]["probability"] = max_sqli_prob
            result["sqli"]["is_vulnerable"] = max_sqli_prob >= 0.70
            return result

    return _FallbackScanner()


# ═══════════════════════════════════════════════════════════════════════════════
# Main Scan Pipeline
# ═══════════════════════════════════════════════════════════════════════════════
def _static_explanation(vuln_type: str) -> str:
    explanations = {
        "XSS": (
            "**Cross-Site Scripting (XSS)** allows attackers to inject malicious scripts into pages viewed by other users.\n\n"
            "**OWASP Mitigation:**\n"
            "- Encode all output using context-aware encoding (HTML, JS, URL)\n"
            "- Implement a strict Content Security Policy (CSP) header\n"
            "- Use `HttpOnly` and `Secure` cookie flags\n"
            "- Validate and sanitize all user inputs server-side\n\n"
            "_Reference: OWASP Top 10 A03:2021 – Injection_"
        ),
        "SQL Injection": (
            "**SQL Injection** allows attackers to interfere with database queries, potentially reading, modifying, or deleting data.\n\n"
            "**OWASP Mitigation:**\n"
            "- Use parameterized queries / prepared statements exclusively\n"
            "- Apply principle of least privilege on DB accounts\n"
            "- Validate and whitelist all user inputs\n"
            "- Use a WAF as an additional layer of defense\n\n"
            "_Reference: OWASP Top 10 A03:2021 – Injection_"
        ),
        "IDOR": (
            "**Insecure Direct Object Reference (IDOR)** occurs when an application exposes internal object references "
            "without proper authorization checks, allowing attackers to access other users' data.\n\n"
            "**OWASP Mitigation:**\n"
            "- Implement server-side access control for every object reference\n"
            "- Replace sequential numeric IDs with UUIDs or session-mapped tokens\n"
            "- Log and alert on unusual access patterns\n"
            "- Perform security testing with multiple user accounts\n\n"
            "_Reference: OWASP Top 10 A01:2021 – Broken Access Control_"
        ),
    }
    return explanations.get(vuln_type, "No explanation available.")


def run_scan(url: str, scan_xss: bool, scan_sqli: bool, scan_idor: bool,
             use_mock: bool, timeout: int, max_payloads: int):
    findings = []
    progress = st.progress(0)
    status = st.empty()

    # ── XSS + SQLi ──────────────────────────────────────────────────────────
    if scan_xss or scan_sqli:
        status.markdown("🕷️ **Step 1/3 — Crawling & injecting payloads…**")
        scanner = get_scanner(use_mock, timeout, max_payloads)
        try:
            result = scanner.scan_url(url)
        except Exception as e:
            result = None
            st.warning(f"⚠️ Scanner error: {e}")

        progress.progress(35)

        if result:
            if scan_xss and result["xss"]["is_vulnerable"]:
                prob = result["xss"]["probability"]
                findings.append({
                    "type": "XSS",
                    "severity": "High" if prob >= 0.85 else "Medium",
                    "confidence": round(prob * 100, 1),
                    "location": url,
                    "description": (
                        f"Cross-Site Scripting detected. "
                        f"{len(result['xss']['vulnerable_payloads'])} payload(s) triggered a vulnerable response."
                    ),
                    "payloads": result["xss"]["vulnerable_payloads"][:3],
                    "details": "",
                    "sources": [],
                })
            if scan_sqli and result["sqli"]["is_vulnerable"]:
                prob = result["sqli"]["probability"]
                findings.append({
                    "type": "SQL Injection",
                    "severity": "Critical" if prob >= 0.85 else "High",
                    "confidence": round(prob * 100, 1),
                    "location": url,
                    "description": (
                        f"SQL Injection detected. "
                        f"{len(result['sqli']['vulnerable_payloads'])} payload(s) triggered a vulnerable response."
                    ),
                    "payloads": result["sqli"]["vulnerable_payloads"][:3],
                    "details": "",
                    "sources": [],
                })

    # ── IDOR ─────────────────────────────────────────────────────────────────
    if scan_idor:
        status.markdown("🔍 **Step 2/3 — Testing for IDOR vulnerabilities…**")
        url_matches = detect_idor_in_url(url)
        if url_matches:
            idor_probes = probe_idor(url, timeout)
            if idor_probes:
                for probe in idor_probes:
                    findings.append({
                        "type": "IDOR",
                        "severity": "High",
                        "confidence": 78.0,
                        "location": probe["test_url"],
                        "description": probe["reason"],
                        "payloads": [{"payload": f"{probe['param']}={probe['tested_id']}", "probability": 0.78}],
                        "details": "",
                        "sources": [],
                    })
            else:
                # Suspicious URL params but couldn't confirm
                findings.append({
                    "type": "IDOR",
                    "severity": "Medium",
                    "confidence": 55.0,
                    "location": url,
                    "description": (
                        f"URL contains object-reference parameter `{url_matches[0]['matched']}`. "
                        "Could not auto-confirm — manual verification recommended."
                    ),
                    "payloads": [],
                    "details": "",
                    "sources": [],
                })

    progress.progress(70)

    # ── RAG AI Analysis ──────────────────────────────────────────────────────
    if findings:
        status.markdown("🤖 **Step 3/3 — Generating AI insights (RAG)…**")
        for finding in findings:
            if RAG_AVAILABLE:
                try:
                    query = (
                        f"Explain {finding['type']} vulnerability: {finding['description']}. "
                        f"Provide OWASP-recommended mitigation steps and examples."
                    )
                    rag_result = generate_augmented_report(query)
                    finding["details"] = rag_result.get("generated_report", "")
                    finding["sources"] = rag_result.get("sources", [])
                except Exception as e:
                    finding["details"] = _static_explanation(finding["type"])
            else:
                finding["details"] = _static_explanation(finding["type"])

    progress.progress(100)
    status.markdown("✅ **Scan complete!**")
    time.sleep(0.5)
    status.empty()
    progress.empty()
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# UI Helpers
# ═══════════════════════════════════════════════════════════════════════════════
SEVERITY_COLORS = {
    "Critical": "#da3633",
    "High":     "#d29922",
    "Medium":   "#388bfd",
    "Low":      "#3fb950",
}

SEV_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

def severity_to_int(s):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(s, 0)


def render_finding_card(finding: dict, idx: int):
    sev = finding.get("severity", "Medium")
    color = SEVERITY_COLORS.get(sev, "#8b949e")
    icon = SEV_ICONS.get(sev, "⚪")
    vuln_type = finding.get("type", "Unknown")
    conf = finding.get("confidence", 0)
    loc = finding.get("location", "")

    label = f"{icon} **{vuln_type}** — {sev} · {conf}% confidence"
    with st.expander(label, expanded=True):
        c1, c2 = st.columns([3, 1])
        with c1:
            st.markdown(f"**📍 Location:** `{loc}`")
            st.markdown(f"**📋 Description:** {finding.get('description', '')}")
        with c2:
            st.markdown(
                f"""<div style="background:{color}22;border:1px solid {color};border-radius:10px;
                    padding:14px;text-align:center;margin-top:8px;">
                    <div style="color:{color};font-size:1.6rem;font-weight:700;">{conf}%</div>
                    <div style="color:var(--text-color);font-size:0.7rem;margin-top:4px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.7;">
                    Confidence</div></div>""",
                unsafe_allow_html=True,
            )

        payloads = finding.get("payloads", [])
        if payloads:
            st.markdown("**🧪 Triggering Payloads:**")
            for p in payloads:
                pl = p.get("payload", str(p)) if isinstance(p, dict) else str(p)
                prob = p.get("probability", 0) if isinstance(p, dict) else 0
                st.code(f"{pl[:120]}  →  prob: {prob:.3f}", language="text")

        st.divider()
        st.markdown("### 🤖 AI Analysis")
        details = finding.get("details", "")
        if details:
            st.markdown(details)
        else:
            st.info("RAG analysis not available for this finding.")

        sources = finding.get("sources", [])
        if sources:
            st.caption("📚 Sources:")
            for src in sources:
                label_src = src.get("source", str(src)) if isinstance(src, dict) else str(src)
                st.caption(f"  · {label_src}")


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ WebScan Pro")
    st.markdown("*AI-Powered Vulnerability Scanner*")
    st.divider()

    page = st.radio(
        "Navigation",
        ["🏠 Dashboard", "📜 History", "ℹ️ About"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("### ⚙️ Scan Configuration")

    scan_xss  = st.toggle("XSS Detection",           value=True)
    scan_sqli = st.toggle("SQL Injection Detection",  value=True)
    scan_idor = st.toggle("IDOR Detection",           value=True)

    use_mock = st.toggle(
        "🔬 Rule-Based Mode",
        value=not UNIFIED_SCANNER_AVAILABLE,
        help="Use pattern matching instead of ML models (faster, no GPU needed).",
    )

    with st.expander("⚙️ Advanced Options"):
        timeout      = st.slider("Request Timeout (s)",    2, 30, 5)
        max_payloads = st.slider("Max Payloads per Type",  3, 50, 10)

    st.divider()
    st.markdown("### 📡 System Status")
    scanner_icon = "🟢" if UNIFIED_SCANNER_AVAILABLE else "🟡"
    rag_icon     = "🟢" if RAG_AVAILABLE else "🔴"
    mode_label   = "ML Mode" if (UNIFIED_SCANNER_AVAILABLE and not use_mock) else "Rule-Based"
    st.markdown(f"{scanner_icon} Scanner: **{mode_label}**")
    st.markdown(f"{rag_icon} RAG Pipeline: **{'Active' if RAG_AVAILABLE else 'Offline'}**")
    st.markdown("🟢 Dashboard: **Online**")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
if page == "🏠 Dashboard":
    st.markdown("# 🛡️ Security Scanner Dashboard")
    st.markdown(
        "Enter a target URL to detect **XSS, SQL Injection, and IDOR** vulnerabilities "
        "using ML models and rule-based analysis, augmented with **RAG AI explanations**."
    )

    col_url, col_btn = st.columns([4, 1])
    with col_url:
        url = st.text_input(
            "Target URL",
            placeholder="https://example.com/profile?id=42",
            label_visibility="collapsed",
        )
    with col_btn:
        st.write("")
        scan_btn = st.button("🚀 Scan", use_container_width=True)

    if scan_btn:
        if not url:
            st.error("Please enter a target URL.")
        elif not url.startswith("http"):
            st.error("URL must begin with `http://` or `https://`")
        elif not any([scan_xss, scan_sqli, scan_idor]):
            st.error("Enable at least one scan type in the sidebar.")
        else:
            st.info(f"🎯 Target: `{url}`")
            findings = run_scan(
                url, scan_xss, scan_sqli, scan_idor,
                use_mock, timeout, max_payloads,
            )

            # Save record
            record = {
                "id":       len(st.session_state.history) + 1,
                "url":      url,
                "date":     datetime.now().strftime("%Y-%m-%d %H:%M"),
                "findings": len(findings),
                "severity": findings[0]["severity"] if findings else "None",
                "data":     findings,
                "config":   {
                    "xss":  scan_xss,
                    "sqli": scan_sqli,
                    "idor": scan_idor,
                    "mode": "rule-based" if use_mock else "ml",
                },
            }
            st.session_state.history.insert(0, record)

            # Summary metrics
            st.divider()
            st.markdown(f"### 📊 Results for `{url}`")

            critical_n = sum(1 for f in findings if f["severity"] == "Critical")
            high_n     = sum(1 for f in findings if f["severity"] == "High")
            medium_n   = sum(1 for f in findings if f["severity"] == "Medium")
            low_n      = sum(1 for f in findings if f["severity"] == "Low")

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.markdown(
                    f'<div class="metric-card"><div class="metric-value" style="color:#da3633">'
                    f'{critical_n}</div><div class="metric-label">Critical</div></div>',
                    unsafe_allow_html=True,
                )
            with m2:
                st.markdown(
                    f'<div class="metric-card"><div class="metric-value" style="color:#d29922">'
                    f'{high_n}</div><div class="metric-label">High</div></div>',
                    unsafe_allow_html=True,
                )
            with m3:
                st.markdown(
                    f'<div class="metric-card"><div class="metric-value" style="color:#388bfd">'
                    f'{medium_n}</div><div class="metric-label">Medium</div></div>',
                    unsafe_allow_html=True,
                )
            with m4:
                st.markdown(
                    f'<div class="metric-card"><div class="metric-value" style="color:#3fb950">'
                    f'{len(findings)}</div><div class="metric-label">Total</div></div>',
                    unsafe_allow_html=True,
                )

            st.markdown("")

            if not findings:
                st.success("✅ No vulnerabilities detected! The target appears clean for the selected scan types.")
            else:
                # Tabs by type
                types_found = list(dict.fromkeys(f["type"] for f in findings))
                tabs = st.tabs(["🔍 All Findings"] + [f"⚠️ {t}" for t in types_found])

                with tabs[0]:
                    sorted_f = sorted(findings, key=lambda f: severity_to_int(f["severity"]), reverse=True)
                    for i, f in enumerate(sorted_f):
                        render_finding_card(f, i)

                for ti, t in enumerate(types_found):
                    with tabs[ti + 1]:
                        for i, f in enumerate([x for x in findings if x["type"] == t]):
                            render_finding_card(f, i)

                # Export
                st.divider()
                st.markdown("### 📤 Export Report")
                ec1, ec2 = st.columns(2)

                report_data = {
                    "scan_meta": {
                        "url":       url,
                        "timestamp": record["date"],
                        "config":    record["config"],
                    },
                    "summary": {
                        "total":    len(findings),
                        "critical": critical_n,
                        "high":     high_n,
                        "medium":   medium_n,
                        "low":      low_n,
                    },
                    "findings": [
                        {k: v for k, v in f.items() if k not in ("details",)}
                        for f in findings
                    ],
                }

                with ec1:
                    st.download_button(
                        "⬇️ Download JSON Report",
                        data=json.dumps(report_data, indent=2),
                        file_name=f"webscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True,
                    )
                with ec2:
                    flat = [
                        {
                            "type":        f["type"],
                            "severity":    f["severity"],
                            "confidence":  f["confidence"],
                            "location":    f["location"],
                            "description": f["description"],
                        }
                        for f in findings
                    ]
                    st.download_button(
                        "⬇️ Download CSV Report",
                        data=pd.DataFrame(flat).to_csv(index=False),
                        file_name=f"webscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: HISTORY
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "📜 History":
    st.markdown("# 📜 Scan History")

    if not st.session_state.history:
        st.info("No scans performed yet. Go to the Dashboard to run your first scan.")
    else:
        history_rows = [
            {
                "ID":           h["id"],
                "Date":         h["date"],
                "URL":          h["url"],
                "Findings":     h["findings"],
                "Top Severity": h.get("severity", "—"),
                "Mode":         h.get("config", {}).get("mode", "—"),
            }
            for h in st.session_state.history
        ]
        st.dataframe(pd.DataFrame(history_rows), use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("### 🔍 Detailed View")
        selected_id = st.selectbox(
            "Select Scan ID",
            [h["id"] for h in st.session_state.history],
        )
        scan = next(h for h in st.session_state.history if h["id"] == selected_id)

        st.markdown(
            f"**URL:** `{scan['url']}`  ·  **Date:** {scan['date']}  ·  **Findings:** {scan['findings']}"
        )

        if scan["data"]:
            for i, f in enumerate(scan["data"]):
                render_finding_card(f, i)
        else:
            st.success("✅ No vulnerabilities found in this scan.")

        col_dl, col_clr = st.columns([2, 1])
        with col_dl:
            st.download_button(
                "⬇️ Export this scan as JSON",
                data=json.dumps(scan, indent=2, default=str),
                file_name=f"scan_{selected_id}.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_clr:
            if st.button("🗑️ Clear All History", use_container_width=True):
                st.session_state.history = []
                st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ABOUT
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "ℹ️ About":
    st.markdown("# ℹ️ About WebScan Pro")

    col_a, col_b = st.columns([3, 1])
    with col_a:
        st.markdown("""
**WebScan Pro** is an automated web vulnerability scanner built for the **Infosys Springboard Internship 6.0**.
It combines machine learning, rule-based heuristics, and Retrieval-Augmented Generation (RAG) to detect and explain web vulnerabilities.

### 🔬 Detection Capabilities

| Module | Method | Target Vulnerability |
|--------|--------|---------------------|
| XSS Detection | PyTorch Bi-LSTM + Attention / CNN + Rule-based | Reflected & Stored XSS |
| SQL Injection | Random Forest + pattern matching fallback | Error-based & Blind SQLi |
| IDOR Detection | Rule-based URL probe + Isolation Forest | Broken Access Control |

### 🤖 AI / RAG Layer

- **Vector Store**: FAISS with `sentence-transformers/all-MiniLM-L6-v2` embeddings
- **LLM**: `google/flan-t5-large` via HuggingFace Endpoint
- **Framework**: LangChain RAG chain with source-cited retrieval
- Provides context-aware vulnerability explanations and OWASP mitigation steps

### 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Language | Python 3.x |
| Frontend | Streamlit |
| ML / DL | scikit-learn, TensorFlow/Keras, PyTorch |
| NLP / RAG | LangChain, HuggingFace, FAISS |
| Data | pandas, numpy, joblib |
| Testing Target | DVWA, OWASP Juice Shop, Custom Mock Server |

### 📊 Trained Models

| Model | Algorithm | Task |
|-------|-----------|------|
| XSS LSTM | Bi-LSTM + Attention | XSS classification |
| XSS CNN | Multi-scale Conv1D | XSS classification |
| SQLi RF | Random Forest | SQL Injection |
| IDOR IF | Isolation Forest | IDOR anomaly detection |
| IDOR AE | Autoencoder (Keras) | IDOR anomaly detection |
        """)
    with col_b:
        st.markdown("""
<div style="background:var(--secondary-background-color);border:1px solid rgba(128,128,128,0.2);border-radius:14px;padding:28px;text-align:center;">
  <div style="font-size:3.5rem">🛡️</div>
  <div style="font-size:1.2rem;font-weight:700;color:var(--text-color);margin-top:10px">WebScan Pro</div>
  <div style="color:var(--text-color);opacity:0.7;font-size:0.78rem;margin-top:6px">v1.0 · Infosys Springboard 6.0</div>
  <hr style="border-color:rgba(128,128,128,0.2);margin:18px 0">
  <div style="color:#3fb950;font-size:0.85rem;text-align:left;line-height:1.9">
    ✅ XSS Detection<br>
    ✅ SQL Injection<br>
    ✅ IDOR Detection<br>
    ✅ RAG AI Analysis<br>
    ✅ JSON/CSV Export<br>
    ✅ Scan History<br>
    ✅ Rule-Based Fallback
  </div>
</div>
        """, unsafe_allow_html=True)
