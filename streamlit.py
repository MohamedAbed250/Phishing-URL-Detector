from __future__ import annotations

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
removed_script_dir = False
if str(SCRIPT_DIR) in sys.path:
    sys.path.remove(str(SCRIPT_DIR))
    removed_script_dir = True

import streamlit as st

if removed_script_dir:
    sys.path.insert(0, str(SCRIPT_DIR))

from execute import (
    DATASET_FILENAME,
    get_evaluation_summary,
    load_arff_dataset,
    load_model,
    predict_batch,
    predict_url,
    preprocess_dataset,
)


st.set_page_config(
    page_title="PhishGuard URL Detector",
    page_icon=":shield:",
    layout="wide",
)

st.markdown(
    """
    <style>
    .hero {
        padding: 1.4rem 1.6rem;
        border-radius: 18px;
        background: linear-gradient(135deg, #0f172a 0%, #134e4a 100%);
        color: #f8fafc;
        margin-bottom: 1.25rem;
    }
    .hero h1 { margin: 0 0 0.4rem 0; font-size: 2.3rem; }
    .hero p { margin: 0.25rem 0; line-height: 1.6; }
    .result-card {
        border-radius: 18px;
        padding: 1.1rem 1.2rem;
        color: white;
        margin: 0.75rem 0 1rem 0;
    }
    .result-card h3, .result-card p { margin: 0.2rem 0; }
    .risk-high { background: linear-gradient(135deg, #991b1b 0%, #dc2626 100%); }
    .risk-medium { background: linear-gradient(135deg, #a16207 0%, #f59e0b 100%); color: #111827; }
    .risk-low { background: linear-gradient(135deg, #166534 0%, #22c55e 100%); }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_artifacts():
    return load_model()


@st.cache_data
def get_dataset():
    return preprocess_dataset(load_arff_dataset(DATASET_FILENAME))


@st.cache_data
def get_dashboard():
    artifacts = get_artifacts()
    return get_evaluation_summary(artifacts, DATASET_FILENAME)


def render_result_card(result: dict) -> None:
    risk_level = result["risk_level"].lower()
    css_class = {"high": "risk-high", "medium": "risk-medium", "low": "risk-low"}[risk_level]
    confidence_pct = round(result["confidence"] * 100, 2)
    phishing_pct = round(result["probabilities"]["phishing"] * 100, 2)
    legitimate_pct = round(result["probabilities"]["legitimate"] * 100, 2)

    st.markdown(
        f"""
        <div class="result-card {css_class}">
            <h3>{result["label"]}</h3>
            <p><strong>Risk level:</strong> {result["risk_level"]}</p>
            <p><strong>Confidence:</strong> {confidence_pct}%</p>
            <p><strong>Phishing probability:</strong> {phishing_pct}%</p>
            <p><strong>Legitimate probability:</strong> {legitimate_pct}%</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_confusion_matrix(metrics: dict) -> None:
    matrix = metrics["confusion_matrix"]
    fig, ax = plt.subplots(figsize=(4.5, 3.8))
    ax.imshow(matrix, cmap="YlGnBu")
    ax.set_xticks([0, 1], labels=["Phishing", "Legitimate"])
    ax.set_yticks([0, 1], labels=["Phishing", "Legitimate"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")
    for row_index, row in enumerate(matrix):
        for column_index, value in enumerate(row):
            ax.text(column_index, row_index, str(value), ha="center", va="center", color="black", fontweight="bold")
    st.pyplot(fig, width="content")


def render_importances(metadata: dict) -> None:
    importances = metadata.get("feature_importances", {})
    if not importances:
        st.info("Feature importance data is not available for this model.")
        return

    ranking = (
        pd.DataFrame(
            [{"Feature": key, "Importance": value} for key, value in importances.items()]
        )
        .sort_values("Importance", ascending=False)
        .head(10)
    )

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(ranking["Feature"], ranking["Importance"], color="#0f766e")
    ax.invert_yaxis()
    ax.set_title("Top Model Feature Importances")
    ax.set_xlabel("Importance")
    st.pyplot(fig, width="stretch")


st.markdown(
    """
    <div class="hero">
        <h1>PhishGuard URL Detector</h1>
        <p>Scan suspicious URLs with a RandomForest phishing classifier built on URL, DNS, HTML, and domain-age signals.</p>
        <p>Predictions are probabilistic and should support human judgment, not replace it. A legitimate result does not guarantee safety.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

artifacts = None
dashboard = None
dataset = None

try:
    artifacts = get_artifacts()
    dashboard = get_dashboard()
    dataset = get_dataset()
except Exception as exc:
    st.error(f"App startup failed: {exc}")
    st.stop()
    raise SystemExit(1)

if dashboard.get("evaluation_type") == "full_dataset_fallback":
    st.warning("Model metadata was not found, so dashboard metrics are being computed on the full dataset. These scores are less trustworthy than a held-out evaluation.")

scan_tab, batch_tab, dashboard_tab, dataset_tab = st.tabs(
    ["Single URL Scan", "Batch CSV", "Model Dashboard", "Dataset Explorer"]
)

with scan_tab:
    st.subheader("Check One URL")
    st.caption("If you enter a domain without a scheme, the app will automatically try `https://` first.")

    with st.form("single_url_form"):
        raw_url = st.text_input("URL", placeholder="example.com or https://example.com/login")
        submitted = st.form_submit_button("Check URL", width="stretch")

    if submitted:
        try:
            with st.spinner("Analyzing URL features and model confidence..."):
                result = predict_url(artifacts, raw_url)

            st.write(f"Normalized URL: `{result['normalized_url']}`")
            render_result_card(result)

            for warning in result["warnings"]:
                st.info(warning)

            left, right = st.columns(2)
            with left:
                st.markdown("**Top suspicious indicators**")
                if result["explanations"]["suspicious"]:
                    for item in result["explanations"]["suspicious"]:
                        st.write(f"- {item['label']}: {item['observed']}")
                else:
                    st.write("No major suspicious indicators were strongly weighted.")

            with right:
                st.markdown("**Top reassuring indicators**")
                if result["explanations"]["reassuring"]:
                    for item in result["explanations"]["reassuring"]:
                        st.write(f"- {item['label']}: {item['observed']}")
                else:
                    st.write("Few strong legitimacy signals were available.")

            st.markdown("**Feature breakdown**")
            st.dataframe(result["feature_table"], width="stretch", hide_index=True)

            with st.expander("Raw extracted metrics", expanded=False):
                metrics_frame = pd.DataFrame(
                    [{"Metric": key, "Value": value} for key, value in result["extraction"].display_metrics.items()]
                )
                st.dataframe(metrics_frame, width="stretch", hide_index=True)
        except Exception as exc:
            st.error(f"Could not analyze that URL: {exc}")

with batch_tab:
    st.subheader("Scan a CSV of URLs")
    st.caption("Upload a CSV with a `url` column. If no obvious URL column exists, the first column will be used.")
    upload = st.file_uploader("Upload CSV", type=["csv"])

    if upload is not None:
        try:
            batch_frame = pd.read_csv(upload)
            st.write("Preview")
            st.dataframe(batch_frame.head(10), width="stretch")

            if st.button("Run Batch Prediction", width="stretch"):
                with st.spinner("Processing uploaded URLs..."):
                    batch_results = predict_batch(artifacts, batch_frame)
                st.dataframe(batch_results, width="stretch", hide_index=True)

                csv_bytes = batch_results.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "Download Results CSV",
                    data=csv_bytes,
                    file_name="phishing_url_predictions.csv",
                    mime="text/csv",
                )
        except Exception as exc:
            st.error(f"Could not process the uploaded CSV: {exc}")

with dashboard_tab:
    st.subheader("Model Performance")
    metrics = dashboard["metrics"]

    accuracy_col, precision_col, recall_col, f1_col = st.columns(4)
    accuracy_col.metric("Accuracy", f"{metrics['accuracy']:.3f}")
    precision_col.metric("Precision", f"{metrics['precision']:.3f}")
    recall_col.metric("Recall", f"{metrics['recall']:.3f}")
    f1_col.metric("F1-score", f"{metrics['f1_score']:.3f}")

    st.caption(f"Evaluation source: `{dashboard.get('evaluation_type', 'unknown')}`")

    chart_col, importance_col = st.columns([1, 1.2])
    with chart_col:
        render_confusion_matrix(metrics)
    with importance_col:
        render_importances(dashboard)

with dataset_tab:
    st.subheader("Training Dataset")
    st.write(f"Rows: `{dataset.shape[0]}`")
    st.write(f"Columns: `{dataset.shape[1]}`")

    label_counts = dataset["result"].map({-1: "Phishing", 1: "Legitimate"}).value_counts()
    st.bar_chart(label_counts)

    preview_size = st.slider("Preview rows", min_value=5, max_value=50, value=10, step=5)
    st.dataframe(dataset.head(preview_size), width="stretch")
