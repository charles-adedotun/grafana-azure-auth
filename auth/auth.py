import os
import logging
from flask import Flask, request, redirect, session, url_for, Response
from msal import ConfidentialClientApplication
import requests
from urllib.parse import urlparse, urljoin
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sockets import Sockets

app = Flask(__name__)
sockets = Sockets(app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecretkey')

# Apply ProxyFix middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Azure B2C Configuration
B2C_TENANT = os.environ.get('B2C_TENANT_NAME')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
USER_FLOW = os.environ.get('SIGNUPSIGNIN_USER_FLOW')
AUTHORITY = f'https://{B2C_TENANT}.b2clogin.com/{B2C_TENANT}.onmicrosoft.com/{USER_FLOW}'
REDIRECT_PATH = "/getAToken"

# Grafana Configuration
GRAFANA_URL = os.environ.get('GRAFANA_URL', 'http://grafana:3000')
ROOT_URL = os.environ.get('ROOT_URL', 'https://localhost')

# MSAL Configuration
msal_app = ConfidentialClientApplication(
    client_id=CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

def get_auth_headers():
    return {
        'X-WEBAUTH-USER': session["user"].get("username", "").strip(),
        'X-WEBAUTH-NAME': session["user"].get("username", ""),
        'X-WEBAUTH-EMAIL': session["user"].get("email", "")
    }

def external_url_for(endpoint, **values):
    """Generate a full URL using the ROOT_URL"""
    path = url_for(endpoint, _external=False, **values)
    return urljoin(ROOT_URL, path)

@app.route("/")
def index():
    if "user" in session:
        logger.info(f"Authenticated user accessing root: {session['user']['username']}")
        return Response("Authenticated. You can now access Grafana.", headers=get_auth_headers())
    logger.info("Unauthenticated user accessing root, redirecting to login")
    return redirect(url_for("login"))

@app.route("/login")
def login():
    if "user" in session:
        logger.info(f"Already authenticated user accessing login: {session['user']['username']}")
        return redirect(ROOT_URL)
    
    session["flow"] = msal_app.initiate_auth_code_flow(
        scopes=[],
        redirect_uri=external_url_for("auth_response")
    )
    logger.info(f"Initiating auth code flow, redirecting to Azure B2C. Redirect URI: {external_url_for('auth_response')}")
    return redirect(session["flow"]["auth_uri"])

@app.route(REDIRECT_PATH)
def auth_response():
    try:
        result = msal_app.acquire_token_by_auth_code_flow(
            session.get("flow", {}),
            request.args
        )
        if "error" in result:
            logger.error(f"Login failed: {result.get('error_description', 'Unknown error')}")
            return f"Login failed: {result.get('error_description', 'Unknown error')}"
        if "id_token_claims" not in result:
            logger.error("Login failed: No token claims received")
            return "Login failed: No token claims received"
        
        session["user"] = {
            "username": result["id_token_claims"].get("name", ""),
            "email": result["id_token_claims"].get("emails", [""])[0] if "emails" in result["id_token_claims"] else ""
        }

        logger.info(f"User logged in successfully with username: {session['user']['username']}")
        return redirect(ROOT_URL)
    except ValueError as ve:
        logger.error(f"Login failed: {str(ve)}")
        return f"Login failed: {str(ve)}"

@app.route('/auth-grafana')
def auth_grafana():
    if "user" not in session:
        logger.info("User session not found, returning 401")
        return Response(status=401)
    
    headers = get_auth_headers()
    logger.info(f"User authenticated, returning headers: {headers}")
    return Response(headers=headers)

@app.route('/health')
def health_check():
    try:
        requests.get(GRAFANA_URL, timeout=5)
        return "Healthy", 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return "Unhealthy", 500

if __name__ == '__main__':
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    logger.info(f"Starting server. GRAFANA_URL is set to: {GRAFANA_URL}")
    logger.info(f"Root URL is set to: {ROOT_URL}")
    server = pywsgi.WSGIServer(('0.0.0.0', 5005), app, handler_class=WebSocketHandler)
    server.serve_forever()