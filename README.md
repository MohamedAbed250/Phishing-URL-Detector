# Phishing URL Detector

Phishing URL Detector is a Streamlit-based phishing URL analysis app built on top of a RandomForest classifier. It classifies a user-entered URL as either:

- `Phishing (-1)`
- `Legitimate (1)`

The project combines lexical URL signals, DNS and SSL checks, lightweight HTML inspection, and a trained machine learning model to provide a prediction, confidence score, risk level, and a feature-by-feature explanation.

## Highlights

- Professional Streamlit dashboard with a landing section and clear disclaimer
- Single URL scanning with validation and automatic `https://` normalization
- Confidence scoring powered by `predict_proba`
- Color-coded result cards for low, medium, and high risk
- Feature explanation and suspicious-indicator summaries
- Batch prediction for CSV uploads with downloadable results
- Model dashboard with confusion matrix, accuracy, precision, recall, and F1-score
- Dataset explorer with preview and label distribution
- Cached URL checks to reduce duplicate network requests
- Robust fallbacks when WHOIS, DNS, SSL, or HTML parsing are unavailable
- Consistent training and inference feature set with model metadata

## Project Structure

```text
Phishing-URL-Detector/
|-- streamlit.py
|-- execute.py
|-- Methods.py
|-- phishing_rf_model.pkl
|-- phishing_rf_model_metadata.json
|-- Training Dataset.arff
`-- README.md
```

## Core Files

### `streamlit.py`

The Streamlit user interface. It provides:

- Landing section and disclaimer
- Single URL prediction flow
- Feature breakdown and explanation table
- Batch CSV analysis
- Model performance dashboard
- Dataset exploration

### `execute.py`

The backend orchestration layer. It handles:

- Model and metadata loading
- Dataset parsing and preprocessing
- Train/test split and training
- Proper SMOTE usage only after the split
- URL prediction
- Batch CSV prediction
- Evaluation summary generation

### `Methods.py`

The feature extraction layer. It includes:

- URL normalization and validation
- DNS, SSL, and WHOIS-based signals
- Cached HTTP fetches for repeated HTML-based checks
- Feature explanation metadata
- Robust fallback behavior when external checks fail

## Model Information

- Model type: `RandomForestClassifier`
- Saved model file: `phishing_rf_model.pkl`
- Metadata file: `phishing_rf_model_metadata.json`
- Feature count: `30`
- Labels:
  - `-1 = Phishing`
  - `1 = Legitimate`

### Current Evaluation Metrics

These values come from the saved metadata file and are based on a holdout split:

- Accuracy: `0.9756`
- Precision: `0.9793`
- Recall: `0.9653`
- F1-score: `0.9723`

Confusion matrix:

```text
[[946, 34],
 [ 20, 1211]]
```

Dataset summary:

- Rows: `11055`
- Columns: `31`

## Improvements Made

This version addresses the main reliability and quality issues from the earlier codebase:

- Removed duplicate and conflicting logic from `Methods.py`
- Centralized the canonical feature list used for both training and inference
- Fixed model loading so it no longer depends on the current working directory
- Added model metadata with versioning, feature names, metrics, and importances
- Switched confidence reporting to `predict_proba`
- Moved SMOTE to the correct place after the train/test split
- Reduced fragile dependence on external services such as search-engine scraping
- Added caching so repeated checks of the same URL do not refetch everything
- Avoided defaulting to phishing on every external-service error
- Added safer timeout behavior for HTTP, DNS, and SSL operations
- Separated UI, model orchestration, and feature extraction more clearly

## Requirements

Recommended Python version:

- `Python 3.11+`

Main packages used:

- `streamlit`
- `pandas`
- `matplotlib`
- `scikit-learn`
- `joblib`
- `requests`
- `beautifulsoup4`
- `imbalanced-learn`
- `python-whois`

Note:

- `beautifulsoup4`, `imbalanced-learn`, and `python-whois` improve feature coverage and training support.
- The app is designed to degrade gracefully if some optional checks are unavailable.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/MohamedAbed250/Phishing-URL-Detector.git
cd Phishing-URL-Detector
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
pip install streamlit pandas matplotlib scikit-learn joblib requests beautifulsoup4 imbalanced-learn python-whois
```

## Running the App

### Terminal

Run the Streamlit app from the project root:

```powershell
.\.venv\Scripts\python.exe -m streamlit run ".\streamlit.py"
```

Then open:

- `http://localhost:8501`

### Important

Do **not** run the app like this:

```powershell
python streamlit.py
```

That launches the file in regular Python mode instead of Streamlit mode and can cause import or `ScriptRunContext` errors.

## Running From PyCharm

To get the local Streamlit link directly inside PyCharm:

1. Open `Run` -> `Edit Configurations...`
2. Create a new `Python` configuration
3. Choose `Module name`
4. Set `Module name` to:

```text
streamlit
```

5. Set `Parameters` to:

```text
run "C:\Users\mkabe\Phishing-URL-Detector\streamlit.py"
```

6. Set `Working directory` to:

```text
C:\Users\mkabe\Phishing-URL-Detector
```

7. Set the interpreter to your project venv:

```text
C:\Users\mkabe\Phishing-URL-Detector\.venv\Scripts\python.exe
```

After running, PyCharm should show a local URL such as:

```text
Local URL: http://localhost:8501
```

## Single URL Prediction

The main UI flow supports:

- One URL input
- Validation of hostname and protocol
- Automatic `https://` prepending when omitted
- Prediction label
- Confidence score
- Risk level
- Suspicious and reassuring signals
- Feature-level explanation table

## Batch CSV Prediction

Upload a CSV file containing a URL column such as:

```csv
url
https://example.com
http://suspicious-site.test/login
```

The app will output:

- URL
- Prediction
- Confidence
- Phishing probability
- Legitimate probability
- Risk level
- Key suspicious features

You can then download the results as CSV.

## Retraining the Model

To retrain the model using the included ARFF dataset:

```powershell
.\.venv\Scripts\python.exe .\execute.py train
```

This will:

- Load `Training Dataset.arff`
- Preprocess the canonical 30-feature dataset
- Split into training and test sets
- Apply SMOTE only on the training partition when available
- Run hyperparameter tuning
- Save the trained model and metadata

## Command-Line Prediction

You can also predict one URL without the UI:

```powershell
.\.venv\Scripts\python.exe .\execute.py predict "https://example.com"
```

## Feature Categories

The model evaluates a mixture of signals, including:

- URL length
- IP address usage
- URL shortening
- `@` symbol usage
- Double-slash redirect patterns
- Hyphenated domains
- Subdomain depth
- HTTPS / SSL status
- Domain age and registration length
- DNS resolution
- Redirect behavior
- Form behavior
- Anchor and tag behavior
- Popup, iframe, and script signals
- Lightweight lexical phishing patterns

## Reliability and Safety Notes

- Predictions are probabilistic, not guarantees.
- A URL classified as legitimate can still be unsafe.
- Some external checks may fail due to network restrictions, timeouts, or unavailable packages.
- The system is designed to continue working with reduced signal coverage instead of crashing.
- To reduce privacy and brittleness concerns, several third-party reputation checks were intentionally minimized.

## Troubleshooting

### `'streamlit' is not recognized`

Run Streamlit through the project interpreter:

```powershell
.\.venv\Scripts\python.exe -m streamlit run ".\streamlit.py"
```

### `module 'streamlit' has no attribute 'set_page_config'`

This usually means the file was run directly with Python instead of through:

```powershell
python -m streamlit run streamlit.py
```

or the PyCharm configuration was set to `Script path` instead of `Module name`.

### WHOIS or HTML feature warnings

These are expected when optional services or dependencies are unavailable. The app will continue with the remaining signals.

## Future Improvements

- Add a `requirements.txt`
- Add unit tests for feature extraction and prediction helpers
- Support asynchronous or queued URL analysis for large batches
- Add Docker support for easier deployment
- Rename `streamlit.py` to `app.py` in a future major cleanup to avoid confusion with the Streamlit package

## Disclaimer

This tool is intended for educational and defensive use. It should support human review, not replace it. Never rely on a single automated prediction when making security decisions.
