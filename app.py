from __future__ import annotations

from datetime import datetime, timezone
import os

from flask import Flask, flash, render_template, request, session

from utils.predictor import PredictionError, PredictionService


EXAMPLE_URLS = [
    "https://www.openai.com",
    "http://verify-account-security-login.com",
    "https://github.com",
    "http://192.168.0.50/update",
]

PROJECT_GITHUB_URL = "https://github.com/MohamedAbed250/Phishing-URL-Detector"
HISTORY_LIMIT = 6


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "phishguard-development-secret")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_SESSION_SECURE", "0") == "1"

    predictor: PredictionService | None = None
    startup_error: str | None = None

    try:
        predictor = PredictionService()
    except Exception as exc:
        startup_error = f"Model startup failed: {exc}"

    def base_context(**extra: object) -> dict[str, object]:
        context = {
            "examples": EXAMPLE_URLS,
            "submitted_url": "",
            "model_info": predictor.dashboard_summary() if predictor is not None else {},
            "service_ready": predictor is not None,
            "startup_error": startup_error,
        }
        context.update(extra)
        return context

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "project_name": "Phishing URL Detector",
            "github_url": PROJECT_GITHUB_URL,
            "current_year": datetime.now(timezone.utc).year,
            "history": session.get("prediction_history", []),
        }

    @app.get("/")
    def home():
        return render_template("index.html", **base_context())

    @app.post("/analyze")
    def analyze():
        raw_url = (request.form.get("url") or "").strip()

        if predictor is None:
            flash(startup_error or "The prediction service is not available right now.", "error")
            return render_template("index.html", **base_context(submitted_url=raw_url)), 503

        if not raw_url:
            flash("Please enter a URL before starting the analysis.", "error")
            return render_template("index.html", **base_context(submitted_url=raw_url)), 400

        try:
            result = predictor.predict(raw_url)
        except PredictionError as exc:
            flash(str(exc), "error")
            return render_template("index.html", **base_context(submitted_url=raw_url)), 400
        except Exception:
            flash("Something went wrong while processing that URL. Please try again.", "error")
            return render_template("index.html", **base_context(submitted_url=raw_url)), 500

        history = session.get("prediction_history", [])
        history.insert(
            0,
            {
                "url": result["normalized_url"],
                "verdict": result["label"],
                "risk_level": result["risk_level"],
                "confidence": result["confidence_percent"],
            },
        )
        session["prediction_history"] = history[:HISTORY_LIMIT]
        session.modified = True

        return render_template("result.html", result=result)

    @app.get("/about")
    def about():
        return render_template("about.html", **base_context())

    @app.get("/health")
    def health():
        status = 200 if predictor is not None else 503
        return {
            "status": "ok" if predictor is not None else "error",
            "service_ready": predictor is not None,
            "model_loaded": predictor is not None,
        }, status

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )
