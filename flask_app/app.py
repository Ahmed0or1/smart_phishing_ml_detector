from flask import Flask, request, render_template
from domain_utils import is_malicious_command
from virus_total import check_virustotal
import pickle, os, datetime, re, subprocess
from urllib.parse import urlparse
from db import get_connection, initialize_db
import tldextract

def extract_registered_domain(url_or_domain):
    extracted = tldextract.extract(url_or_domain)
    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else url_or_domain

def extract_features_from_url(url):
    length_url = len(url)
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    parsed = urlparse(url)
    hostname = parsed.netloc
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    ip_flag = 1 if ip_pattern.match(hostname) else 0
    return [length_url, nb_dots, nb_hyphens, ip_flag]

def get_whois_info(domain):
    domain = extract_registered_domain(domain)
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, check=True)
        output = result.stdout
        data = {
            "registrant": "Not Available",
            "registrar": "Not Available",
            "domain_status": "Not Available",
            "expiration_date": "Not Available",
            "whois_server": "Not Available",
            "updated_date": "Not Available",
            "creation_date": "Not Available",
            "abuse_email": "Not Available",
            "abuse_phone": "Not Available",
            "whois_last_update": "Not Available"
        }
        for line in output.splitlines():
            line = line.strip()
            lower_line = line.lower()
            if lower_line.startswith("registrant name:"):
                data["registrant"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("registrar:") and "whois" not in lower_line:
                data["registrar"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("domain status:") and data["domain_status"] == "Not Available":
                data["domain_status"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("registry expiry date:"):
                data["expiration_date"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("registrar whois server:"):
                data["whois_server"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("updated date:"):
                data["updated_date"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("creation date:"):
                data["creation_date"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("registrar abuse contact email:"):
                data["abuse_email"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("registrar abuse contact phone:"):
                data["abuse_phone"] = line.split(":", 1)[1].strip()
            elif lower_line.startswith("last update of whois database:"):
                data["whois_last_update"] = line.split(":", 1)[1].strip()
        return data
    except Exception:
        return {
            "registrant": "Not Available",
            "registrar": "Not Available",
            "domain_status": "Not Available",
            "expiration_date": "Not Available",
            "whois_server": "Not Available",
            "updated_date": "Not Available",
            "creation_date": "Not Available",
            "abuse_email": "Not Available",
            "abuse_phone": "Not Available",
            "whois_last_update": "Not Available"
        }

ML_MODEL_PATH = os.path.expanduser("~/Desktop/phishing/model_training/phishing_model.pkl")
if os.path.exists(ML_MODEL_PATH):
    with open(ML_MODEL_PATH, "rb") as f:
        phishing_detector = pickle.load(f)
else:
    from sklearn.dummy import DummyClassifier
    import numpy as np
    dummy = DummyClassifier(strategy="constant", constant=0)
    dummy.fit(np.array([[1, 2, 3, 4]]), [0])
    phishing_detector = dummy

app = Flask(__name__)
initialize_db()

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        long_url = request.form.get("input", "").strip()
        result["long_url"] = long_url

        if is_malicious_command(long_url):
            result["error"] = "Suspicious command detected!"
            return render_template("index.html", result=result)

        cleaned_domain = extract_registered_domain(long_url)
        result["domain"] = cleaned_domain

        archive_url = f"https://web.archive.org/web/20250000000000*/{cleaned_domain}"
        result["archive_url"] = archive_url

        vt_data = check_virustotal(cleaned_domain)
        attributes = vt_data.get("data", {}).get("attributes", {}) if "error" not in vt_data else {}

        analysis = attributes.get("last_analysis_stats", {})
        result["analysis"] = {
            "malicious": analysis.get("malicious", "Not Available"),
            "suspicious": analysis.get("suspicious", "Not Available")
        }
        result["reputation"] = attributes.get("reputation", "Not Available")
        creation_timestamp = attributes.get("creation_date", None)
        result["creation_date"] = datetime.datetime.utcfromtimestamp(creation_timestamp).strftime('%Y-%m-%d') if creation_timestamp else "Not Available"

        ssl_info = attributes.get("last_https_certificate", {})
        validity = ssl_info.get("validity", {})
        result["ssl"] = {
            "valid_from": validity.get("not_before", "Not Available"),
            "valid_until": validity.get("not_after", "Not Available"),
            "issuer": ssl_info.get("issuer", {}).get("CN", "Not Available")
        }

        dns_records = attributes.get("last_dns_records", [])
        result["dns"] = {
            "total_records": len(dns_records) if dns_records else "Not Available",
            "key_records": [record["type"] for record in dns_records] if dns_records else "Not Available"
        }

        result["whois"] = get_whois_info(cleaned_domain)

        if phishing_detector:
            features = extract_features_from_url(long_url)
            try:
                prediction = phishing_detector.predict([features])[0]
                result["model_prediction"] = "legitimate" if prediction == 0 else "phishing" if prediction == 1 else str(prediction)
            except Exception as e:
                result["model_prediction"] = f"Error predicting: {str(e)}"
        else:
            result["model_prediction"] = "Model not loaded"

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO history (
                long_url, domain, malicious_count, suspicious_count, reputation,
                creation_date, ssl_valid_from, ssl_valid_until, ssl_issuer,
                dns_total_records, dns_key_records,
                whois_registrant, whois_registrar, whois_domain_status, whois_expiration_date,
                model_prediction, archive_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            long_url,
            cleaned_domain,
            result["analysis"]["malicious"] if isinstance(result["analysis"]["malicious"], int) else 0,
            result["analysis"]["suspicious"] if isinstance(result["analysis"]["suspicious"], int) else 0,
            str(result["reputation"]),
            result["creation_date"],
            result["ssl"]["valid_from"],
            result["ssl"]["valid_until"],
            result["ssl"]["issuer"],
            result["dns"]["total_records"] if isinstance(result["dns"]["total_records"], int) else 0,
            ",".join(result["dns"]["key_records"]) if isinstance(result["dns"]["key_records"], list) else "Not Available",
            result["whois"]["registrant"],
            result["whois"]["registrar"],
            result["whois"]["domain_status"],
            result["whois"]["expiration_date"],
            result["model_prediction"],
            result["archive_url"]
        ))
        conn.commit()
        conn.close()

    return render_template("index.html", result=result)

@app.route("/history")
def history():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return render_template("history.html", rows=rows)

@app.route("/dataset")
def dataset():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return render_template("dataset.html", rows=rows)

if __name__ == "__main__":
    app.run(debug=True)
