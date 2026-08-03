# Phishing URL Detector

A complete, modern, and portfolio-ready phishing URL detection web application built with **Flask**, **scikit-learn**, and a production-style frontend.

The application predicts whether a submitted URL is **legitimate** or **phishing**, then explains the result with feature-level insight such as URL structure, redirects, HTTPS usage, DNS status, domain age, and suspicious lexical patterns.

## Project Overview

This project demonstrates:

- Full-stack Python web development with Flask
- Machine learning inference in a web application
- Modular feature extraction and prediction layers
- Responsive frontend design with HTML, CSS, and JavaScript
- Clean repository structure suitable for a GitHub portfolio

The goal is not only to classify URLs, but to present the result in a clear, professional, and interpretable way.

## Features

- Modern responsive home page with hero section and navigation
- URL validation with automatic `https://` normalization
- ML-powered phishing prediction using a trained RandomForest model
- Confidence scores from `predict_proba`
- Risk-level classification: Low, Medium, High
- Feature explanation with readable descriptions
- Suspicious indicator summary
- Prediction history stored during the session
- Dark mode toggle
- Loading state on analysis
- Copy result button
- Example URLs for fast testing
- About page explaining model, dataset, and architecture
- Favicon and polished UI for portfolio presentation

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

## Folder Structure

```text
phishing-url-detector/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── model/
│   ├── phishing_model.pkl
│   ├── phishing_model_metadata.json
│   └── train_model.py
│
├── utils/
│   ├── feature_extraction.py
│   └── predictor.py
│
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── script.js
│   └── images/
│       └── favicon.svg
│
├── templates/
│   ├── index.html
│   ├── result.html
│   ├── about.html
│   └── layout.html
│
└── data/
    ├── train.csv
    ├── test.csv
    └── Training Dataset.arff
```

## How It Works

### 1. User submits a URL

The homepage accepts a user-entered URL and validates that it is structurally usable.

### 2. Features are extracted

The backend extracts a combination of lexical and network-aware features, including:

- URL length
- Number of dots
- Number of subdomains
- HTTPS usage
- IP address usage
- Hyphen count
- Suspicious keywords
- Digit count
- Redirect behavior
- DNS resolution
- Domain age
- HTML and script signals

### 3. Model inference runs

The extracted feature vector is passed into a pre-trained `RandomForestClassifier`.

### 4. The app returns

- Prediction label
- Confidence score
- Risk level
- Feature breakdown
- Suspicious and reassuring signals

## Machine Learning Notes

- Model type: `RandomForestClassifier`
- Labels:
  - `-1` = Phishing
  - `1` = Legitimate
- Confidence is based on `predict_proba`
- Training and inference share one canonical feature list
- SMOTE is applied only after the train/test split during retraining
- External checks degrade gracefully if DNS, WHOIS, SSL, or HTML fetches fail

## Installation

### 1. Clone the project

```bash
git clone <your-repository-url>
cd phishing-url-detector
```

### 2. Create a virtual environment

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

## Usage

### Run the Flask app

```powershell
python app.py
```

Then open:

- `http://127.0.0.1:5000`

### Try a URL

Use the home page URL input and click **Analyze URL**.

Example values:

- `https://github.com`
- `https://www.openai.com`
- `http://verify-account-login-alert.com`

## Retraining the Model

If you want to retrain the model using the CSV files:

```powershell
python -m model.train_model
```

This will:

- Load `data/train.csv` and `data/test.csv`
- Apply SMOTE when available
- Tune a RandomForest model
- Save `model/phishing_model.pkl`
- Save `model/phishing_model_metadata.json`

## Security and Robustness

The application includes:

- URL validation before prediction
- Friendly error messages
- Safe handling for invalid URLs
- Request timeouts
- Cached repeated URL checks
- Graceful fallback if WHOIS, DNS, SSL, or HTML checks fail
- Separation of UI, model logic, and feature extraction

## Portfolio Value

This project is suitable for a software engineering or ML internship portfolio because it demonstrates:

- Backend architecture
- Web application development
- ML deployment
- Maintainable Python code
- UI polish and usability
- Documentation quality

## Future Improvements

- Export scan reports as PDF or CSV
- Add asynchronous batch analysis
- Add Docker support
- Add unit and integration tests
- Add API endpoints for external clients
- Add user accounts and persistent scan history

## License

This project is provided for educational and portfolio use. You can add your preferred open-source license such as MIT.
