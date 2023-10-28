# import streamlit as st
# import requests
# from requests.auth import HTTPBasicAuth

# # OAuth2 Flow Yahoo Doc
# # https://developer.yahoo.com/oauth2/guide/flows_authcode/

# # Client_ID and Secret from https://developer.yahoo.com/apps/
# cid = st.secrets["YAHOO_CLIENT_ID"]
# cse = st.secrets["YAHOO_CLIENT_SECRET"]

# # Ensure that the Client ID and Secret are set
# if cid is None or cse is None:
#     st.error("Client ID or Client Secret is not set. Please set the YAHOO_CLIENT_ID and YAHOO_CLIENT_SECRET environment variables.")
#     st.stop()

# # URL for st button with Client ID in query string
# redirect_uri = "https://yahoo-ff-test.streamlit.app/"  # Change to your app's callback URL
# auth_page = f'https://api.login.yahoo.com/oauth2/request_auth?client_id={cid}&redirect_uri={redirect_uri}&response_type=code'

# # Show ST Button to open Yahoo OAuth2 Page
# if 'auth_code' not in st.session_state:
#     st.session_state['auth_code'] = ''

# if 'access_token' not in st.session_state:
#     st.session_state['access_token'] = ''

# if st.button('Auth with Yahoo'):
#     st.session_state['auth_code'] = ''
#     st.session_state['access_token'] = ''
#     st.rerun()

# if st.session_state['auth_code']:
#     st.success('Authorization code received!')
#     st.write(f'Your authorization code is: {st.session_state["auth_code"]}')
# else:
#     st.write("Click the button above to authenticate with Yahoo.")
#     st.write(f"[Authenticate with Yahoo]({auth_page})")

# # Get the token
# if st.session_state['auth_code'] and not st.session_state['access_token']:
#     basic = HTTPBasicAuth(cid, cse)
#     _data = {
#         'redirect_uri': redirect_uri,
#         'code': st.session_state['auth_code'],
#         'grant_type': 'authorization_code'
#     }

#     try:
#         r = requests.post('https://api.login.yahoo.com/oauth2/get_token', data=_data, auth=basic)
#         r.raise_for_status()  # Will raise an exception for HTTP errors
#         token_data = r.json()
#         st.session_state['access_token'] = token_data.get('access_token', '')
#         st.success('Access token received!')
#         st.write('Access token:', st.session_state['access_token'])
#     except requests.exceptions.HTTPError as err:
#         st.error(f"HTTP error occurred: {err}")
#     except Exception as err:
#         st.error(f"An error occurred: {err}")

# # Use the access token
# if st.session_state['access_token']:
#     # Add your code here to use the access token and interact with Yahoo's API
#     st.write("Now you can use the access token to interact with Yahoo's API.")


import streamlit as st
import requests
from requests.auth import HTTPBasicAuth

#OAuth2 Flow Yahoo Doc
#https://developer.yahoo.com/oauth2/guide/flows_authcode/

#Client_ID and Secret from https://developer.yahoo.com/apps/
cid = st.secrets["YAHOO_CLIENT_ID"]
cse = st.secrets["YAHOO_CLIENT_SECRET"]

#URL for st button with Client ID in query string
auth_page =f'https://api.login.yahoo.com/oauth2/request_auth?client_id={cid}&redirect_uri=oob&response_type=code'

#Show ST Button to open Yahoo OAuth2 Page
st.link_button('Auth with Yahoo',url=auth_page) 
code = ''

#Get Auth Code pasted by user
code=st.text_input("Enter Code") 
st.write(f'Your code is :{code}')

#Hack to spin and wait for user. Proper way is to use a form and callback
while code=='': 
  st.write()

#Get the token
basic = HTTPBasicAuth(cid, cse) 

_data = {
  'redirect_uri':'oob',
'code':code,
'grant_type':'authorization_code' 
}

r=requests.post('https://api.login.yahoo.com/oauth2/get_token',data=_data,auth=basic)
#Spit out the token, ideally save this as a cookie in users browser
st.write(r.content)