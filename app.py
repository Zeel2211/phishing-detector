# app.py
import streamlit as st
import numpy as np
import pickle
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Load model and scaler
with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

# Define feature order
features_order = [
    'google_index', 'page_rank', 'web_traffic', 'domain_age',
    'nb_hyperlinks', 'nb_www', 'longest_word_path',
    'ratio_intHyperlinks', 'ratio_extHyperlinks',
    'phish_hints', 'safe_anchor', 'ratio_digits_url',
    'ratio_extRedirection', 'avg_word_path'
]

# Auto-extract features
def extract_features(url):
    try:
        res = requests.get(url if url.startswith('http') else f"http://{url}", timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
    except:
        soup = BeautifulSoup("", "html.parser")

    hyperlinks = soup.find_all('a')
    nb_hyperlinks = len(hyperlinks)
    nb_www = url.count('www')
    path_parts = urlparse(url).path.split('/')
    longest_word = max(path_parts, key=len) if path_parts else ''
    longest_word_path = len(longest_word)
    internal = external = 0
    for a in hyperlinks:
        href = a.get('href')
        if href:
            if href.startswith('/'):
                internal += 1
            elif href.startswith('http'):
                external += 1
    total = internal + external if internal + external else 1
    ratio_int = internal / total
    ratio_ext = external / total
    phish_keywords = ['login', 'secure', 'account', 'bank', 'verify']
    phish_hints = int(any(word in url.lower() for word in phish_keywords))
    safe_anchor = sum(1 for a in hyperlinks if a.get('href') in [None, '', '#']) / nb_hyperlinks if nb_hyperlinks else 0
    digits = sum(c.isdigit() for c in url)
    ratio_digits = digits / len(url) if url else 0
    avg_len = sum(len(w) for w in path_parts if w) / len([w for w in path_parts if w]) if path_parts else 0

    return {
        'nb_hyperlinks': nb_hyperlinks,
        'nb_www': nb_www,
        'longest_word_path': longest_word_path,
        'ratio_intHyperlinks': ratio_int,
        'ratio_extHyperlinks': ratio_ext,
        'phish_hints': phish_hints,
        'safe_anchor': safe_anchor,
        'ratio_digits_url': ratio_digits,
        'ratio_extRedirection': 0.0,
        'avg_word_path': avg_len
    }

# Streamlit UI
st.title("🔐 Phishing URL Detector")

url = st.text_input("🌐 Enter Website URL", "www.example.com")

st.subheader("📋 Manual Features")
google_index = st.selectbox("Is it Google Indexed?", [0, 1])
page_rank = st.slider("Page Rank (0-10)", 0, 10, 5)
web_traffic = st.number_input("Web Traffic", min_value=0, value=500000000)
domain_age = st.number_input("Domain Age (in days)", min_value=0, value=1000)

if st.button("🔍 Detect"):
    manual = {
        'google_index': google_index,
        'page_rank': page_rank,
        'web_traffic': web_traffic,
        'domain_age': domain_age
    }

    auto = extract_features(url)
    combined = {**manual, **auto}

    # Ensure correct order
    input_data = np.array([combined[feat] for feat in features_order]).reshape(1, -1)
    input_scaled = scaler.transform(input_data)
    prediction = model.predict(input_scaled)[0]
    label = "Phishing" if prediction > 0.5 else "Legitimate"
    confidence = float(prediction)

    st.success(f"🛡️ Result: {label}")
    st.info(f"🔢 Confidence: {confidence:.4f}")
