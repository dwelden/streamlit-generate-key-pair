# Based on https://medium.com/snowflake/generating-private-and-public-keys-using-snowflake-snowpark-46ca9c518fc3
# and https://danflippo.medium.com/generating-private-and-public-keys-using-streamlit-in-snowflake-a4ea1b48d5a1

import streamlit as st
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import rsa
import base64, secrets, string
from zipfile import ZipFile

def generate_passphrase():
    """ Generate random passphrase to encrypt PEM Private Key"""
    default_passphrase_length = 20
    characters = string.digits+string.ascii_letters
    passphrase = ''.join(
        (secrets.choice(characters) for i in range(default_passphrase_length))
    )
    return passphrase

def generate_key_pair(passphrase):
    """ Generate key pair and return as dictionary """
    pem = s.Encoding.PEM
    der = s.Encoding.DER
    pkcs8 = s.PrivateFormat.PKCS8
    pub = s.PublicFormat.SubjectPublicKeyInfo

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    file_names = (
        "encrypted_pem_private_key.pem",
        "pem_private_key.pem",
        "pem_public_key.pem",
        "passphrase.txt",
        "private_key.key",
        "public_key.key"
    )

    keys = (
        rsa_key.private_bytes(pem, pkcs8, s.BestAvailableEncryption(passphrase.encode('utf-8'))).decode('utf-8'),
        rsa_key.private_bytes(pem, pkcs8, s.NoEncryption()).decode('utf-8'),
        rsa_key.public_key().public_bytes(pem, pub).decode('utf-8'),
        passphrase,
        base64.b64encode(rsa_key.private_bytes(der, pkcs8, s.NoEncryption())).decode('utf-8'),
        base64.b64encode(rsa_key.public_key().public_bytes(der, pub)).decode('utf-8')
    )

    d = dict(zip(file_names, keys))

    return d

def zip_for_download(keypair_dict):
    """ Write the keys from the dictionary into a zip file"""
    zip_name = "keypair.zip"

    with ZipFile(zip_name, "w") as z:
        for file_name, key in keypair_dict.items():
            z.writestr(file_name, key)

    return zip_name

if "passphrase" not in st.session_state:
    st.session_state.passphrase = generate_passphrase()

st.title(f"Generate Key Pair")
st.image(image="images/keypair.jpeg")
st.text("You can use the randomly generated passphrase or supply your own")
st.session_state.passphrase = st.text_input(
    label=f"Enter Passphrase for Encrypted PEM Private Key",
    value=st.session_state.passphrase
)

keypair_dict = generate_key_pair(st.session_state.passphrase)
zip_name = zip_for_download(keypair_dict)

with open(zip_name, 'rb') as z:
    st.download_button(
        label     = "Download key pair files",
        data      = z,
        file_name = zip_name
    )
