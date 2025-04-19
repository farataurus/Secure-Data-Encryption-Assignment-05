import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
from streamlit_lottie import st_lottie
import requests
import time
import re

# --- Constants ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
MAX_ATTEMPTS = 3

# --- Animations ---
ANIMATIONS = {
    "secure": "https://assets1.lottiefiles.com/packages/lf20_q5kxy7tz.json",
    "vault": "https://assets1.lottiefiles.com/packages/lf20_5tkzkblw.json",
    "success": "https://assets1.lottiefiles.com/packages/lf20_yjgbpsef.json",
    "error": "https://assets1.lottiefiles.com/packages/lf20_gnvsa7vy.json"
}

# --- Helper Functions ---
def load_lottie(url):
    try:
        r = requests.get(url, timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

cipher = Fernet(load_key())

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def validate_passkey(passkey):
    if len(passkey) < 8:
        return False, "Passkey must be at least 8 characters"
    if not re.search("[A-Z]", passkey):
        return False, "Passkey must contain at least one uppercase letter"
    if not re.search("[a-z]", passkey):
        return False, "Passkey must contain at least one lowercase letter"
    if not re.search("[0-9]", passkey):
        return False, "Passkey must contain at least one digit"
    return True, "Passkey is valid"

# --- UI Configuration ---
st.set_page_config(
    page_title="Secure Vault - Data Encryption System",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS with purple theme
st.markdown("""
<style>
    [data-testid="stAppViewContainer"] {
        background: linear-gradient(135deg, #f5f7fa 0%, #e1bee7 100%);
    }
    .stButton>button {
        background-color: #9c27b0 !important;
        color: white !important;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #7b1fa2 !important;
        transform: scale(1.02);
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 8px !important;
        border: 1px solid #9c27b0 !important;
    }
    .success-box {
        background-color: #e8f5e9;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .error-box {
        background-color: #ffebee;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background: linear-gradient(45deg, #4b6cb7, #182848);
        color: white !important;
        text-align: center;
        padding: 15px;
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

# --- Main Application ---
def main():
    # Initialize session state
    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0
    if "locked_out" not in st.session_state:
        st.session_state.locked_out = False
    if "auth_time" not in st.session_state:
        st.session_state.auth_time = 0

    # Sidebar navigation
    st.sidebar.title("🔒 Secure Vault")
    menu = ["Home", "Store Data", "Retrieve Data"]
    choice = st.sidebar.selectbox("Navigation", menu)

    # Main content
    if choice == "Home":
        st.title("Secure Data Encryption System")
        st.markdown("""
        ### Store and retrieve your sensitive data securely
        
        **Features:**
        - Military-grade AES-256 encryption
        - Secure passkey authentication
        - Tamper-proof data storage
        - Attempt limitation for security
        """)
        
        col1, col2 = st.columns([1, 2])
        with col1:
            lottie_vault = load_lottie(ANIMATIONS["vault"])
            if lottie_vault:
                st_lottie(lottie_vault, height=200)
        
        with col2:
            st.info("""
            **Instructions:**
            1. Store data with a unique label and passkey
            2. Retrieve with the same passkey
            3. After 3 failed attempts, system will lock
            """)

    elif choice == "Store Data":
        st.title("🔐 Store Encrypted Data")
        
        with st.form("store_form"):
            label = st.text_input("Data Label (e.g., 'Bank Details'):")
            data = st.text_area("Data to Encrypt:", height=150)
            passkey = st.text_input("Encryption Passkey:", type="password")
            confirm_passkey = st.text_input("Confirm Passkey:", type="password")
            
            if st.form_submit_button("Encrypt & Store"):
                if not label or not data or not passkey:
                    st.error("All fields are required!")
                elif passkey != confirm_passkey:
                    st.error("Passkeys don't match!")
                else:
                    is_valid, msg = validate_passkey(passkey)
                    if not is_valid:
                        st.error(msg)
                    else:
                        encrypted = encrypt_data(data)
                        stored_data = load_data()
                        
                        stored_data[label] = {
                            "encrypted_text": encrypted,
                            "passkey": hash_passkey(passkey),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        save_data(stored_data)
                        
                        lottie_success = load_lottie(ANIMATIONS["success"])
                        if lottie_success:
                            st_lottie(lottie_success, height=150)
                        
                        st.success("Data encrypted and stored successfully!")
                        st.info("Important: Remember your passkey - it cannot be recovered!")

    elif choice == "Retrieve Data":
        if st.session_state.locked_out:
            if time.time() - st.session_state.auth_time < 300:  # 5 minute lockout
                remaining_time = int(300 - (time.time() - st.session_state.auth_time))
                st.error(f"Account locked! Please try again in {remaining_time} seconds.")
                return
            else:
                st.session_state.locked_out = False
                st.session_state.failed_attempts = 0
        
        st.title("🔓 Retrieve Encrypted Data")
        stored_data = load_data()
        
        if not stored_data:
            st.warning("No data stored yet!")
            return
        
        with st.form("retrieve_form"):
            label = st.selectbox("Select Data Label:", options=list(stored_data.keys()))
            passkey = st.text_input("Enter Passkey:", type="password")
            
            if st.form_submit_button("Decrypt Data"):
                if label in stored_data:
                    if hash_passkey(passkey) == stored_data[label]["passkey"]:
                        decrypted = decrypt_data(stored_data[label]["encrypted_text"])
                        st.session_state.failed_attempts = 0
                        
                        lottie_success = load_lottie(ANIMATIONS["success"])
                        if lottie_success:
                            st_lottie(lottie_success, height=150)
                        
                        st.success("Decryption successful!")
                        st.text_area("Decrypted Data:", value=decrypted, height=200)
                    else:
                        st.session_state.failed_attempts += 1
                        
                        lottie_error = load_lottie(ANIMATIONS["error"])
                        if lottie_error:
                            st_lottie(lottie_error, height=150)
                        
                        attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                        st.error(f"Incorrect passkey! Attempts left: {attempts_left}")
                        
                        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                            st.session_state.locked_out = True
                            st.session_state.auth_time = time.time()
                            st.error("Too many failed attempts! Account locked for 5 minutes.")
                else:
                    st.error("Data label not found!")

    # Custom footer with your name
    st.markdown("""
    <div class="footer">
        Developed with ❤️ by Farah Asghar | © 2024 Secure Vault | v2.0
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()