
import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import re
import ipaddress

# Load the saved model
model_data = joblib.load("phishing_model.joblib")
model = model_data["model"]
feature_columns = model_data["feature_columns"]


import re
from urllib.parse import urlparse

def extract_url_features(url):
    url = str(url)

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features = {
        'URLLength': len(url),
        'DomainLength': len(domain),
        'IsDomainIP': int(bool(re.match(
            r'^\d+\.\d+\.\d+\.\d+$', domain.split(':')[0]
        ))),
        'NoOfDots': url.count('.'),
        'NoOfHyphens': url.count('-'),
        'NoOfAt': url.count('@'),
        'NoOfQuestionMark': url.count('?'),
        'NoOfAmpersand': url.count('&'),
        'NoOfDigits': sum(c.isdigit() for c in url),
        'NoOfSubdomains': max(
            0, domain.split(':')[0].count('.') - 1
        ),
        'HasHTTPS': int(parsed.scheme == 'https'),
        'HasSuspiciousWords': int(
            any(word in url.lower() for word in [
                'login', 'verify', 'update',
                'secure', 'account', 'banking'
            ])
        ),
        'PathLength': len(path)
    }

    return features


st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Phishing URL Detection System")
st.write("Enter a website URL to check its predicted classification.")

st.info(
    "This machine-learning model provides an estimate, "
    "not a guarantee that a website is safe."
)

url = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)

if st.button("Check URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL.")
    elif not url.strip().lower().startswith(("http://", "https://")):
        st.warning("Enter a URL starting with http:// or https://.")
    else:
        try:
            features = extract_url_features(url.strip())
            input_data = pd.DataFrame([features])
            input_data = input_data[feature_columns]

            prediction = int(model.predict(input_data)[0])

            if prediction == 0:
                st.error("⚠️ Result: Potential Phishing URL")
            else:
                st.success("✅ Result: Not Phishing")

        except Exception as e:
            st.error(f"Unable to analyze URL: {e}")
