# app.py

import streamlit as st
import pickle
from urllib.parse import urlparse
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests

# Load trained XGBoost model
filename = 'xgboost_model.pkl'
loaded_model = pickle.load(open(filename, 'rb'))

# Shortening services regex
SHORTENING_SERVICES = r"bit\.ly|goo\.gl|shorte\.st|tinyurl|t\.co|is\.gd|cli\.gs|tiny\.cc|url4\.eu|ow\.ly|j\.mp"

# -------------------------------
# 🔎 Feature extraction functions
# -------------------------------

def clean_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        return domain.split(':')[0]
    except:
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
    path_segments = urlparse(url).path.split('/')
    return sum(1 for segment in path_segments if segment)

def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

def http_domain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

def tiny_url(url):
    return 1 if re.search(SHORTENING_SERVICES, url) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen(
            "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        return 1 if int(rank) < 100000 else 0
    except:
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
    except:
        return 1

def domain_end(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        remaining_months = (expiration_date - datetime.now()).days / 30
        return 0 if remaining_months >= 6 else 1
    except:
        return 1

def iframe(response):
    if response == "":
        return 1
    return 1 if not re.findall(r"<iframe>|<frameBorder>", response.text) else 0

def mouse_over(response):
    if response == "":
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def right_click(response):
    if response == "":
        return 1
    return 1 if not re.findall(r"event.button ?== ?2", response.text) else 0

def forwarding(response):
    if response == "":
        return 1
    return 1 if len(response.history) > 2 else 0

# ----------------------------
# 🔧 Main feature extractor
# ----------------------------
def feature_extraction(url):
    features = []

    # Address bar-based features
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))

    # Domain-based features
    try:
        domain_clean = clean_domain(url)
        domain_name = whois.whois(domain_clean)
        features.append(0)  # DNS record present
        features.append(web_traffic(url))  # Optional
        features.append(domain_age(domain_name))
        features.append(domain_end(domain_name))
    except:
        features.extend([1, 1, 1, 1])

    # HTML/JS-based features
    try:
        response = requests.get(url, timeout=5)
        features.append(iframe(response))
        features.append(mouse_over(response))
        features.append(right_click(response))
        features.append(forwarding(response))
    except:
        features.extend([1, 1, 1, 1])

    return features

# ----------------------------------
# 🚀 Model prediction with breakdown
# ----------------------------------
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
        if safe_points >= 12:
            
            st.success(f"✅ The URL '{url}' has {safe_points} safe points and is likely **Safe**.")
        else:
            
            st.error(f"❌ The URL '{url}' has {safe_points} safe points and is likely **Malicious**.")

    return prediction

# -------------------------
# 🎨 Streamlit UI starts
# -------------------------
st.set_page_config(page_title="URL Maliciousness Predictor", page_icon="🔍")
st.title("🔍 URL Maliciousness Predictor")
st.markdown("Enter a URL below to check if it might be **malicious** or **safe** based on machine learning and handcrafted features.")

url = st.text_input("🌐 Enter a URL to check:")

if st.button("🚦 Predict"):
    if url:
        prediction = predict_url(url, show_debug=True)
    else:
        st.warning("⚠️ Please enter a valid URL.")
