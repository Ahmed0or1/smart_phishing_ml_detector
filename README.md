
# Smart Phishing ML Detector

**Smart Phishing ML Detector** is a Flask-based web application that uses machine learning to detect phishing URLs. It integrates with the VirusTotal API, WHOIS tool (native in Kali Linux), and stores historical data and analysis in a local SQLite database. It supports dataset visualization and CSV export features.

---
## 👨‍💻 Contributors 💻

- **Ahmed Alghamdi** – `202400437`  
- **Ahmed Aljadani** – `202400626`  
- **Supervisor:** Dr. Qazi Emad ULHaq  
  Department of Forensic Science, Naif Arab University for Security Sciences  
  Riyadh, Kingdom of Saudi Arabia
  
## 🔍 Project Overview

This system scans URLs and performs the following actions:

- **Extracts features** from a given URL
- **Predicts phishing** or legitimate using a trained ML model
- **Queries VirusTotal** for analysis data
- **Fetches WHOIS info** using the Kali `whois` tool
- **Generates visual reports** during training (figures saved)
- **Stores scan history** in `phishing_data.db`
- **Exports full dataset** from the browser in `.csv` format
- **Displays Wayback Machine** archive preview

---
## 📦 Dataset

- Source: [Kaggle - Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset?select=dataset_phishing.csv)
---
## ✅ System Requirements

- Python 3.10+
- Kali Linux recommended (includes WHOIS tool)
- Internet access for VirusTotal API queries
---

## 📁 Project Structure

```bash
smart_phishing_ml_detector/
├── flask_app/
│   ├── app.py                   # Main Flask app
│   ├── db.py                    # SQLite DB setup
│   ├── domain_utils.py          # Domain parsing & validation
│   ├── virus_total.py           # VirusTotal API client
│   ├── phishing_data.db         # Created automatically on first run
│   ├── templates/
│   │   ├── index.html           # Homepage: scan form + results
│   │   ├── history.html         # Scan history table
│   │   ├── dataset.html         # Dataset view with export button
│   ├── static/
│   │   ├── style.css
│   │   ├── logo.png
├── model_training/
│   ├── train_model.py                # Basic training script
│   ├── figures.py                    # figure generation
│   ├── phishing_model.pkl            # Trained model
│   ├── figure1_workflow.png
│   ├── figure2_class_distribution.png
│   ├── figure3_feature_importance.png
│   ├── figure4_nb_dots_distribution.png
│   ├── figure5_results_table.png
├── dataset/
│   ├── phishing_data.csv             # Kaggle dataset
├── env/                              # Virtual environment (optional)
├── requirements.txt                  # Python dependencies
```
## 🔧 Setup Instructions

### Step 1 – Create and activate a virtual environment

```bash
$ python3 -m venv env
$ source env/bin/activate
```

### Step 2 – Install dependencies

```bash
$ pip install -r requirements.txt
```

### Step 3 – Train the model

```bash
$ python model_training/train_model.py
```

This script will read the dataset, extract features, train a Random Forest classifier, and save the model to `phishing_model.pkl`.

### Step 4 – Run the Flask web app

```bash
$ python flask_app/app.py
```

Then open your browser and visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---
## 🌐 Web Pages
| Page             | Description                                      |
|------------------|--------------------------------------------------|
| `/`              | **Home**: Enter URL, scan, and show result      |

![home](https://raw.githubusercontent.com/Ahmed0or1/smart_phishing_ml_detector/refs/heads/main/flask_app/static/home.PNG)
| Page             | Description                                      |
|------------------|--------------------------------------------------|
| `/history`       | **Scan History**: View all scanned entries        |

![history](https://raw.githubusercontent.com/Ahmed0or1/smart_phishing_ml_detector/refs/heads/main/flask_app/static/history.PNG)
| Page             | Description                                      |
|------------------|--------------------------------------------------|
| `/dataset`       -> **Dataset View**: Export full dataset in CSV |

![dataset](https://raw.githubusercontent.com/Ahmed0or1/smart_phishing_ml_detector/refs/heads/main/flask_app/static/dataset.PNG)

