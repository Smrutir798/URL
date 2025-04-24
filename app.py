# app.py

import streamlit as st
import pickle
from urllib.parse import urlparse
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib.parse
import urllib.request
from datetime import datetime
import requests

# Constants
FILENAME = 'xgboost_model.pkl'
SHORTENING_SERVICES = r"bit\.ly|goo\.gl|shorte\.st|tinyurl|t\.co|is\.gd|cli\.gs|tiny\.cc|url4\.eu|ow\.ly|j\.mp"
SAFE_THRESHOLD = 11

# Load the model
loaded_model = pickle.load(open(FILENAME, 'rb'))

# Utility functions
def clean_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc.split(':')[0]
    except Exception:
        return ""

def having_ip(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except ValueError:
        return 0

def have_at_sign(url):
    return 1 if "@" in url else 0

def get_length(url):
    return 1 if len(url) >= 54 else 0

def get_depth(url):
    return sum(1 for segment in urlparse(url).path.split('/') if segment)

def redirection(url):
    return 1 if url.rfind('//') > 6 else 0

def http_domain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

def tiny_url(url):
    return 1 if re.search(SHORTENING_SERVICES, url) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        url_encoded = urllib.parse.quote(url)
        rank = BeautifulSoup(
            urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={url_encoded}").read(),
            "xml"
        ).find("REACH")['RANK']
        return 1 if int(rank) < 100000 else 0
    except Exception:
        return 1

def domain_age(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        age_in_months = (expiration_date - creation_date).days / 30
        return 0 if age_in_months >= 6 else 1
    except Exception:
        return 1

def domain_end(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        remaining_months = (expiration_date - datetime.now()).days / 30
        return 0 if remaining_months >= 6 else 1
    except Exception:
        return 1

def iframe(response):
    return 1 if not re.findall(r"<iframe>|<frameBorder>", response.text) else 0

def mouse_over(response):
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def right_click(response):
    return 1 if not re.findall(r"event.button ?== ?2", response.text) else 0

def forwarding(response):
    return 1 if len(response.history) > 2 else 0

# Feature extraction
def feature_extraction(url):
    features = []

    # Address bar-based features
    features.extend([
        having_ip(url),
        have_at_sign(url),
        get_length(url),
        get_depth(url),
        redirection(url),
        http_domain(url),
        tiny_url(url),
        prefix_suffix(url)
    ])

    # Domain-based features
    try:
        domain_clean = clean_domain(url)
        domain_name = whois.whois(domain_clean)
        features.extend([
            0,  # DNS record present
            web_traffic(url),
            domain_age(domain_name),
            domain_end(domain_name)
        ])
    except Exception:
        features.extend([1, 1, 1, 1])

    # HTML/JS-based features
    try:
        response = requests.get(url, timeout=5)
        features.extend([
            iframe(response),
            mouse_over(response),
            right_click(response),
            forwarding(response)
        ])
    except Exception:
        features.extend([1, 1, 1, 1])

    return features

# Prediction and breakdown
def predict_url(url, show_debug=False):
    features = feature_extraction(url)
    prediction = loaded_model.predict([features])[0]

    if show_debug:
        st.subheader("🔍 Feature Breakdown:")
        feature_labels = [
            "IP Address in URL", "‘@’ Symbol", "URL Length ≥ 54", "Path Depth",
            "Redirection ‘//’", "HTTPS in Domain", "Shortened URL", "Prefix/Suffix (-)",
            "DNS Record Present", "Web Traffic < 100k", "Domain Age < 6 months", "Domain Expiry < 6 months",
            "IFrame Detected", "Mouse Over Events", "Right Click Disabled", "Redirect History > 2"
        ]
        feature_data = [{"Feature": label, "Status": "✅ Safe" if val == 0 else "⚠️ Suspicious"} 
                        for label, val in zip(feature_labels, features)]
        st.table(feature_data)

        safe_points = sum(1 for val in features if val == 0)
        if safe_points >= SAFE_THRESHOLD:
            st.success(f"✅ The URL '{url}' has {safe_points} safe points and is likely **Safe**.")
        else:
            st.error(f"❌ The URL '{url}' has {safe_points} safe points and is likely **Malicious**.")

    return prediction

# Streamlit UI
st.set_page_config(page_title="URL Maliciousness Predictor", page_icon="🔍")
st.title("🔍 URL Maliciousness Predictor")
st.markdown("Enter a URL below to check if it might be **malicious** or **safe** based on machine learning and handcrafted features.")

url = st.text_input("🌐 Enter a URL to check:")

if st.button("🚦 Predict"):
    if url:
        predict_url(url, show_debug=True)
    else:
        st.warning("⚠️ Please enter a valid URL.")
