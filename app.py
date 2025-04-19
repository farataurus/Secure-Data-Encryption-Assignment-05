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
USER_DB = "users.json"
MAX_ATTEMPTS = 3

# --- Lottie Animations ---
ANIMATIONS = {
    "register": "https://assets1.lottiefiles.com/packages/lf20_jcikwtux.json",
    "login": "https://assets1.lottiefiles.com/packages/lf20_hu9cd9.json",
    "success": "https://assets1.lottiefiles.com/packages/lf20_yjgbpsef.json",
    "error": "https://assets1.lottiefiles.com/packages/lf20_gnvsa7vy.json",
    "vault": "https://assets1.lottiefiles.com/packages/lf20_5tkzkblw.json"
}

# --- Helper Functions ---
def load_lottie(url):
    try:
        r = requests.get(url, timeout=5)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# --- Page Config ---
st.set_page_config(
    page_title="Farii Secure Data Encryption App",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# --- Custom CSS ---
st.markdown("""
<style>
    .stButton>button {
        background-color: #00ACC1 !important;
        color: white !important;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #00838F !important;
        transform: scale(1.02);
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 8px !important;
        border: 1px solid #00ACC1 !important;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #FCE4EC, #F8BBD0);
    }
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #C2185B;
        color: white;
        text-align: center;
        padding: 15px;
        font-family: 'Arial', sans-serif;
        box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
    }
    .quote {
        font-style: italic;
        font-size: 0.9em;
        margin-bottom: 5px;
    }
    .credit {
        font-size: 0.8em;
    }
    .success-box {
        background-color: #E8F5E9;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .error-box {
        background-color: #FFEBEE;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# --- Footer Component ---
def footer():
    st.markdown("""
    <div class="footer">
        <div class="quote">"Work hard. Push yourself, because no one else is going to do it for you." - Bruce Schneier</div>
        <div class="credit">Created with ❤ by Farah Asghar </div>
    </div>
    """, unsafe_allow_html=True)

# --- Authentication ---
def register_user():
    st.title("👤 Create Your Account")
    col1, col2 = st.columns([1, 2])
    with col1:
        lottie_register = load_lottie(ANIMATIONS["register"])
        if lottie_register:
            st_lottie(lottie_register, height=200)
    with col2:
        with st.form("register_form"):
            username = st.text_input("Choose a Username:")
            email = st.text_input("Email Address:")
            password = st.text_input("Create Password:", type="password")
            confirm_password = st.text_input("Confirm Password:", type="password")
            if st.form_submit_button("Register"):
                users = load_users()
                if username in users:
                    st.error("Username already exists!")
                    return
                if password != confirm_password:
                    st.error("Passwords do not match!")
                    return
                is_valid, message = validate_password(password)
                if not is_valid:
                    st.error(message)
                    return
                users[username] = {
                    "email": email,
                    "password": hash_password(password),
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                save_users(users)
                st.session_state.current_user = username
                st.session_state.is_logged_in = True
                st.success("Account created successfully! You are now logged in.")
                time.sleep(2)
                st.rerun()

def login_user():
    st.title("🔑 Welcome Back!")
    col1, col2 = st.columns([1, 2])
    with col1:
        lottie_login = load_lottie(ANIMATIONS["login"])
        if lottie_login:
            st_lottie(lottie_login, height=200)
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username:")
            password = st.text_input("Password:", type="password")
            if st.form_submit_button("Login"):
                users = load_users()
                if username not in users:
                    st.error("Username not found!")
                    return
                if hash_password(password) != users[username]["password"]:
                    if "login_attempts" not in st.session_state:
                        st.session_state.login_attempts = 0
                    st.session_state.login_attempts += 1
                    attempts_left = MAX_ATTEMPTS - st.session_state.login_attempts
                    st.error(f"Invalid password! Attempts left: {attempts_left}")
                    if st.session_state.login_attempts >= MAX_ATTEMPTS:
                        st.error("Account locked due to too many failed attempts.")
                        time.sleep(3)
                        st.stop()
                    return
                st.session_state.current_user = username
                st.session_state.is_logged_in = True
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()

# --- Main App ---
def main_app():
    st.sidebar.title("🔐 Secure Data Encryption App")
    st.sidebar.markdown(f"Welcome, *{st.session_state.current_user}*")
    menu = ["Dashboard", "Store Secrets", "Retrieve Secrets", "Account Settings", "Logout"]
    choice = st.sidebar.radio("Navigation", menu)

    if choice == "Dashboard":
        st.title("🌟 Mehak's Secure Data Vault")
        st.markdown("""
        ### Your Personal Security Fortress
        *Safeguard your digital life with:*
        - Military-grade AES-256 encryption
        - Personalized user accounts
        - Secure secret storage
        """)
    elif choice == "Store Secrets":
        st.title("💌 Store Your Secrets")
        with st.form("store_form"):
            label = st.text_input("Secret Label:")
            data = st.text_area("Confidential Data:")
            passkey = st.text_input("Encryption Passkey:", type="password")
            if st.form_submit_button("🔒 Lock Away Secret"):
                if len(label) < 3 or not data.strip() or len(passkey) < 8:
                    st.error("Please fill all fields properly.")
                else:
                    encrypted = encrypt_data(data)
                    stored_data = load_data()
                    if st.session_state.current_user not in stored_data:
                        stored_data[st.session_state.current_user] = {}
                    stored_data[st.session_state.current_user][label] = {
                        "data": encrypted,
                        "passkey": hash_password(passkey),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    save_data(stored_data)
                    st.success("✅ Secret locked away safely!")
    elif choice == "Retrieve Secrets":
        st.title("🔓 Retrieve Your Secrets")
        stored_data = load_data()
        user_data = stored_data.get(st.session_state.current_user, {})
        if not user_data:
            st.warning("You haven't stored any secrets yet.")
            return
        with st.form("retrieve_form"):
            label = st.selectbox("Select Secret:", options=list(user_data.keys()))
            passkey = st.text_input("Enter Passkey:", type="password")
            if st.form_submit_button("🔑 Unlock Secret"):
                if hash_password(passkey) == user_data[label]["passkey"]:
                    decrypted = decrypt_data(user_data[label]["data"])
                    st.text_area("Your Secret:", value=decrypted, height=200)
                else:
                    st.error("Wrong passkey!")
    elif choice == "Account Settings":
        st.title("⚙ Account Settings")
        users = load_users()
        user_info = users.get(st.session_state.current_user)
        if not user_info:
            st.error("User info not found. Please login again.")
            st.session_state.is_logged_in = False
            st.session_state.current_user = None
            time.sleep(2)
            st.rerun()
        st.write(f"👤 Username: {st.session_state.current_user}")
        st.write(f"📧 Email: {user_info['email']}")
        st.write(f"🕒 Member since: {user_info['created_at']}")
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password:", type="password")
            new_password = st.text_input("New Password:", type="password")
            confirm_password = st.text_input("Confirm New Password:", type="password")
            if st.form_submit_button("Update Password"):
                if hash_password(current_password) != user_info["password"]:
                    st.error("Incorrect current password")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    is_valid, msg = validate_password(new_password)
                    if not is_valid:
                        st.error(msg)
                    else:
                        users[st.session_state.current_user]["password"] = hash_password(new_password)
                        save_users(users)
                        st.success("Password updated successfully!")
    elif choice == "Logout":
        st.session_state.is_logged_in = False
        st.session_state.current_user = None
        st.success("Logged out successfully!")
        time.sleep(1)
        st.rerun()

# --- Session State Initialization ---
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# --- App Launch ---
if not st.session_state.is_logged_in:
    st.sidebar.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=80)
    st.sidebar.markdown("### Secure Data Encryption App")
    auth_choice = st.sidebar.radio("Menu", ["Login", "Register"])
    if auth_choice == "Login":
        login_user()
    else:
        register_user()
else:
    main_app()

# --- Sticky Footer ---
footer()
