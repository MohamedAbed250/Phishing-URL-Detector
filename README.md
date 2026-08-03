# Phishing URL Detector

A modern, portfolio-ready Flask web application that predicts whether a URL is legitimate or phishing and explains the result with readable security signals.

## Overview

This project combines a trained Random Forest classifier with a clean web interface for URL analysis. Users can submit a URL and receive:

- A phishing or legitimate verdict
- Confidence from `predict_proba`
- Low, Medium, or High risk classification
- Suspicious and reassuring feature explanations
- A detailed feature breakdown table

The app is structured to be easy to demo, maintain, and extend.

## Features

- Responsive landing page with a professional hero section
- Automatic `https://` normalization when the scheme is missing
- URL validation before inference
- Model-backed phishing classification
- Confidence scoring and risk-level labeling
- Explainable output based on extracted features
- Session-based prediction history
- Dark mode toggle
- Loading state and copy-result action
- About page with model and dataset details
- Health endpoint for quick local or deployment checks

## Tech Stack

### Frontend

- HTML5
- CSS3
- JavaScript

### Backend

- Python
- Flask

### Machine Learning

- scikit-learn
- pandas
- numpy
- joblib

### Supporting Libraries

- requests
- beautifulsoup4
- python-whois
- imbalanced-learn

## Project Structure

```text
phishing-url-detector/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── model/
│   ├── phishing_model.pkl
│   ├── phishing_model_metadata.json
│   └── train_model.py
├── utils/
│   ├── feature_extraction.py
│   └── predictor.py
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── script.js
│   └── images/
│       └── favicon.svg
├── templates/
│   ├── index.html
│   ├── result.html
│   ├── about.html
│   └── layout.html
└── data/
    ├── train.csv
    ├── test.csv
    └── Training Dataset.arff
```

## How It Works

1. The user submits a URL.
2. The backend normalizes and validates it.
3. `utils/feature_extraction.py` builds the canonical phishing feature set.
4. `utils/predictor.py` loads the saved model and runs inference.
5. The UI renders the verdict, confidence, risk level, and explanation cards.

## Core Feature Signals

The model and explanation layer use signals such as:

- URL length
- Subdomain depth
- HTTPS and SSL state
- IP address usage
- Hyphenated domains
- Redirect behavior
- DNS resolution
- Domain age and registration length
- HTML link and form behavior
- Suspicious lexical patterns

## Machine Learning Notes

- Model: `RandomForestClassifier`
- Labels:
  - `-1` = Phishing
  - `1` = Legitimate
- Confidence is taken from `predict_proba`
- Training and inference use one canonical feature list
- SMOTE is applied only to the training split during retraining
- External checks fail gracefully instead of crashing the app

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/MohamedAbed250/Phishing-URL-Detector.git
cd phishing-url-detector
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the App

```powershell
python app.py
```

Then open:

- `http://127.0.0.1:5000`
- `http://127.0.0.1:5000/health`

## Example URLs

- `https://github.com`
- `https://www.openai.com`
- `http://verify-account-login-alert.com`

## Retraining the Model

To retrain the phishing model:

```powershell
python -m model.train_model
```

This will:

- Load `data/train.csv` and `data/test.csv`
- Apply SMOTE to the training data when available
- Tune a Random Forest model
- Save `model/phishing_model.pkl`
- Save `model/phishing_model_metadata.json`

## Reliability and Security

The app includes:

- Safe URL validation
- Request timeouts
- Cached repeated checks
- Graceful degradation when WHOIS, DNS, SSL, or HTML lookups fail
- Session cookie defaults for safer local usage
- Startup health reporting when model artifacts are missing

## Recent Cleanup

This repository was cleaned up to improve maintainability and GitHub presentation:

- Refactored app startup and request handling
- Added a `/health` route
- Removed hardcoded debug-on behavior
- Improved `.gitignore` coverage for local environment noise
- Fixed the README structure rendering and run instructions

## Future Improvements

- Add batch CSV analysis
- Add automated tests
- Add Docker support
- Expose a JSON API
- Persist scan history in a database

## License

This project is provided for educational and portfolio use. You can add an MIT or similar open-source license if you want to publish it formally.
