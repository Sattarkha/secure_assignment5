import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Function to hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to generate a key from passkey (for encryption)
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Function to encrypt data
def encrypt_data(data, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(data_id, encrypted_data, passkey):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['key'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_data.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Function to generate a unique ID for the data
def generate_data_id():
    return str(uuid.uuid4())

# Function to reset the failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0
    st.session_state.last_attempt_time = 0

# Function to change page
def change_page(page_name):
    st.session_state.current_page = page_name

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Check if too many failed attempts
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("Too many failed attempts! Reauthorization required.")

# Display the current page
if st.session_state.current_page == "Home":
    st.subheader("🏡 Welcome to the Secure Data Encryption System!")
    st.write("Use this app to **securely store and retrieve your data** using a unique passkey.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")
    st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data.")

elif st.session_state.current_page == "Store Data":
    st.subheader("🔐 Store Your Data Securely")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a passkey to encrypt your data:", type="password")
    confirm_passkey = st.text_input("Confirm your passkey:", type="password")

    if st.button("Encrypt and Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠ Passkeys do not match!")
            else:
                data_id = generate_data_id()
                encrypted_text = encrypt_data(user_data, passkey)
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[data_id] = {
                    'encrypted_text': encrypted_text,
                    'key': hashed_passkey
                }
                st.success("✅ Data stored successfully!")
                st.code(data_id, language='text')
                st.info("⚠ Keep this ID safe! You will need it to retrieve your data.")
        else:
            st.error("⚠ All fields are required!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔑 Retrieve Your Data")
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"⚠ You have {attempts_remaining} attempts remaining.")
    data_id = st.text_input("Enter the ID of the data you want to retrieve:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt and Retrieve"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                decrypted_text = decrypt_data(data_id, encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Data retrieved successfully!")
                    st.markdown("**Decrypted Data:**")
                    st.code(decrypted_text, language='text')
                else:
                    st.error(f"⚠ Incorrect passkey! Remaining attempts: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Invalid data ID!")

            if st.session_state.failed_attempts >= 3:
                st.warning("Too many failed attempts! Redirecting to login page.")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("⚠ Both fields are required!")

elif st.session_state.current_page == "Login":
    st.subheader("🔑 Reauthorize Access")
    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts >= 3:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⚠ Too many failed attempts! Please wait {remaining_time} seconds before trying again.")
    else:
        login_passkey = st.text_input("Enter Master Password:", type="password")
        if st.button("Login"):
            if login_passkey == "master_password":
                reset_failed_attempts()
                st.success("✅ Reauthorization successful!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect Master Password!")

st.markdown("---")
st.markdown("Made with ❤️ by [Abdul Sattar]")
