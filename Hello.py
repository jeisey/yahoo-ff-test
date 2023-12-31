import streamlit as st
import requests
import json
import os
import time
import tempfile
from requests.auth import HTTPBasicAuth
from yfpy.query import YahooFantasySportsQuery

# OAuth2 Flow Yahoo Doc
# https://developer.yahoo.com/oauth2/guide/flows_authcode/

# Client_ID and Secret from https://developer.yahoo.com/apps/
cid = st.secrets["YAHOO_CLIENT_ID"]
cse = st.secrets["YAHOO_CLIENT_SECRET"]

# Ensure that the Client ID and Secret are set
if cid is None or cse is None:
    st.error("Client ID or Client Secret is not set. Please set the YAHOO_CLIENT_ID and YAHOO_CLIENT_SECRET environment variables.")
    st.stop()

# URL for st button with Client ID in query string
redirect_uri = "oob" #"oob"  # Out of band # "https://yahoo-ff-test.streamlit.app/" for dev version
auth_page = f'https://api.login.yahoo.com/oauth2/request_auth?client_id={cid}&redirect_uri={redirect_uri}&response_type=code'

# Show ST Button to open Yahoo OAuth2 Page
if 'auth_code' not in st.session_state:
    st.session_state['auth_code'] = ''

if 'access_token' not in st.session_state:
    st.session_state['access_token'] = ''

if 'refresh_token' not in st.session_state:
    st.session_state['refresh_token'] = ''

st.write("1. Click the link below to authenticate with Yahoo and get the authorization code.")
st.write(f"[Authenticate with Yahoo]({auth_page})")

# Get Auth Code pasted by user
st.write("2. Paste the authorization code here:")
auth_code = st.text_input("Authorization Code")

if auth_code:
    st.session_state['auth_code'] = auth_code
    st.success('Authorization code received!')
    st.write(f'Your authorization code is: {auth_code}')

# Get the token
if st.session_state['auth_code'] and not st.session_state['access_token']:
    basic = HTTPBasicAuth(cid, cse)
    _data = {
        'redirect_uri': redirect_uri,
        'code': st.session_state['auth_code'],
        'grant_type': 'authorization_code'
    }

    try:
        r = requests.post('https://api.login.yahoo.com/oauth2/get_token', data=_data, auth=basic)
        r.raise_for_status()  # Will raise an exception for HTTP errors
        token_data = r.json()
        st.session_state['access_token'] = token_data.get('access_token', '')
        st.session_state['refresh_token'] = token_data.get('refresh_token', '')
        st.session_state['token_time'] = time.time()
        st.success('Access token received!')
        st.write('Full token response:', token_data)
    except requests.exceptions.HTTPError as err:
        st.error(f"HTTP error occurred: {err}")
    except Exception as err:
        st.error(f"An error occurred: {err}")

# Use the access token
if st.session_state['access_token']:
    st.write("Now you can use the access token to interact with Yahoo's API.")

    # Allow user to input league ID
    league_id = st.text_input("Enter your Yahoo Fantasy Sports league ID:")
    if league_id:
        # Create a temporary directory to store the token and private files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Define the paths to the token and private files
            token_file_path = os.path.join(temp_dir, "token.json")
            private_file_path = os.path.join(temp_dir, "private.json")

            # Create the token file with all necessary details
            token_data = {
                "access_token": st.session_state['access_token'],
                "consumer_key": cid,
                "consumer_secret": cse,
                "guid": None,
                "refresh_token": st.session_state['refresh_token'],
                "expires_in": 3600, 
                "token_time": st.session_state['token_time'],
                "token_type": "bearer"
                }
            with open(token_file_path, 'w') as f:
                json.dump(token_data, f)

            # Create the private file with consumer key and secret
            private_data = {
                "consumer_key": cid,
                "consumer_secret": cse,
            }
            with open(private_file_path, 'w') as f:
                json.dump(private_data, f)

            # Initialize the YahooFantasySportsQuery
            st.write("Initializing yf_query...")
            yf_query = YahooFantasySportsQuery(
                league_id=league_id,
                auth_dir=temp_dir,
                game_code="nfl"
            )
            st.write("Completed intialization, setting token_time...")
            yf_query.oauth.token_time = time.time() - 3500

            # Now you can use yf_query to make queries to Yahoo Fantasy Sports API
            # Example: Get league settings
            league_settings = yf_query.get_league_settings()
            st.write("League Settings:", league_settings)
            st.write("Done, cleaning up now...")
            ## Add function to cleanup() the temp files
            st.write("Done!")
