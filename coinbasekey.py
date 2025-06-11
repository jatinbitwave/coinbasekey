import streamlit as st
import json
import time
import requests
import jwt
from jwt import InvalidTokenError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

API_URL = "https://api.coinbase.com/api/v3/brokerage/accounts"

st.set_page_config(page_title="Coinbase Key Validator", page_icon="🔐")
st.title("🔐 Coinbase Retail Key Validator")

st.markdown("""
This app validates your Coinbase Advanced Trade API v3 credentials securely by:
- Verifying private key formatting
- Generating a JWT using ES256
- Testing authentication against Coinbase's brokerage API

Upload your `cdp_api_key.json` file to begin.
""")

uploaded_file = st.file_uploader("Upload your `cdp_api_key.json` file", type="json")

def format_private_key(pem_str):
    if "\\n" in pem_str:
        pem_str = pem_str.replace("\\n", "\n")
    return pem_str.encode()

def validate_private_key(pem_bytes):
    try:
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        st.error(f"Invalid private key: {e}")
        return None

def generate_jwt(api_key, private_key):
    now = int(time.time())
    payload = {
        'iss': api_key,
        'sub': api_key,
        'aud': 'cdp-api.coinbase.com',
        'nbf': now,
        'exp': now + 300,
        'iat': now
    }
    try:
        token = jwt.encode(
            payload,
            private_key,
            algorithm='ES256'
        )
        return token
    except Exception as e:
        st.error(f"Error generating JWT: {e}")
        return None

def test_credentials(api_key, jwt_token):
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'CB-ACCESS-KEY': api_key,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(API_URL, headers=headers)
        if response.status_code == 200:
            st.success("✅ Credentials are valid. Successfully accessed the API.")
        else:
            st.error(f"❌ Failed to authenticate. Status Code: {response.status_code}")
            st.code(response.text, language='json')
    except Exception as e:
        st.error(f"Error during API request: {e}")

if uploaded_file:
    try:
        creds = json.load(uploaded_file)
        required_fields = ['name', 'key', 'secret', 'passphrase', 'private_key']
        for field in required_fields:
            if field not in creds:
                st.error(f"Missing required field: {field}")
                st.stop()

        pem_bytes = format_private_key(creds['private_key'])
        private_key = validate_private_key(pem_bytes)
        if not private_key:
            st.stop()

        jwt_token = generate_jwt(creds['key'], private_key)
        if jwt_token:
            st.text("JWT generated successfully.")
            test_credentials(creds['key'], jwt_token)

    except json.JSONDecodeError:
        st.error("Invalid JSON file uploaded.")
    except Exception as e:
        st.error(f"Unexpected error: {e}")

st.markdown("""
---
**Note:** This app requires a full Python environment with `ssl` and `cryptography`. Deploy it on [Streamlit Cloud](https://streamlit.io/cloud) using GitHub for full compatibility.
""")
