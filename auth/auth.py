import os
import logging
from flask import Flask, request, redirect, session, url_for, Response
from msal import ConfidentialClientApplication
import requests
from urllib.parse import urlparse, urlunparse
from werkzeug.exceptions import InternalServerError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecretkey')

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

# MSAL Configuration
msal_app = ConfidentialClientApplication(
    client_id=CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

@app.route("/")
def index():
    if "user" not in session:
        logger.info("User not authenticated, redirecting to login")
        return redirect(url_for("login"))
    logger.info("User authenticated, redirecting to Grafana")
    return redirect(url_for("auth_grafana"))

@app.route("/login")
def login():
    session["flow"] = msal_app.initiate_auth_code_flow(
        scopes=[],
        redirect_uri=url_for("auth_response", _external=True)
    )
    logger.info("Initiating auth code flow, redirecting to Azure B2C")
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
        
        # Store user information in session after successful login
        session["user"] = {
            "username": result["id_token_claims"].get("name", ""),
            "email": result["id_token_claims"].get("emails", [""])[0] if "emails" in result["id_token_claims"] else ""
        }

        logger.info(f"User logged in successfully with username: {session['user']['username']}")
        return redirect(url_for("auth_grafana"))
    except ValueError as ve:
        logger.error(f"Login failed: {str(ve)}")
        return f"Login failed: {str(ve)}"

@app.route('/auth-grafana', methods=['GET'])
def auth_grafana():
    if "user" not in session:
        logger.info("User session not found, redirecting to login")
        return redirect(url_for("login"))
    
    try:
        # Prepare headers
        headers = {
            'X-WEBAUTH-USER': session["user"].get("username", ""),
            'X-WEBAUTH-NAME': session["user"].get("username", ""),
            'X-WEBAUTH-EMAIL': session["user"].get("email", "")
        }
        
        logger.info(f"Headers being sent to Grafana: {headers}")

        # Forward the request to Grafana
        grafana_response = requests.get(
            GRAFANA_URL + request.full_path.replace('/auth-grafana', ''),
            headers=headers,
            allow_redirects=False  # Disable automatic redirects
        )

        # If a redirect is required, manually handle it and reapply headers
        if grafana_response.is_redirect:
            redirect_url = grafana_response.headers.get('Location')
            logger.info(f"Handling redirect to {redirect_url} and reapplying headers")

            # Parse the redirect URL and replace 'localhost' with the correct Grafana service name and port
            parsed_url = urlparse(redirect_url)
            if parsed_url.hostname == 'localhost':
                parsed_url = parsed_url._replace(netloc='grafana:3000')
                redirect_url = urlunparse(parsed_url)

            grafana_response = requests.get(
                redirect_url,
                headers=headers,
                allow_redirects=False
            )

        # Log the response headers for debugging
        logger.info(f"Response headers from Grafana: {grafana_response.headers}")

        # Create a new response object, but explicitly remove Transfer-Encoding if it's set
        response = Response(grafana_response.content, status=grafana_response.status_code)
        for key, value in grafana_response.headers.items():
            if key.lower() != 'transfer-encoding':
                response.headers[key] = value

        logger.info(f"Proxying request to Grafana with status: {grafana_response.status_code}")

        return response
    except Exception as e:
        logger.error(f"Error in auth_grafana route: {str(e)}")
        return InternalServerError("An unexpected error occurred during Grafana authentication")

@app.route('/public/<path:path>', methods=['GET'])
def proxy_static(path):
    try:
        # Forward the static file requests to Grafana
        grafana_response = requests.get(
            f"{GRAFANA_URL}/public/{path}",
            allow_redirects=False
        )

        # Log the response headers for debugging
        logger.info(f"Response headers from Grafana: {grafana_response.headers}")

        # Return the response from Grafana
        response = Response(grafana_response.content, status=grafana_response.status_code)
        for key, value in grafana_response.headers.items():
            response.headers[key] = value

        logger.info(f"Proxying static file request for {path} with status: {grafana_response.status_code}")

        return response
    except Exception as e:
        logger.error(f"Error proxying static file request: {str(e)}")
        return InternalServerError("An unexpected error occurred while proxying static file request")

@app.route('/health')
def health_check():
    try:
        requests.get(GRAFANA_URL)
        return "Healthy", 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return "Unhealthy", 500

if __name__ == '__main__':
    app.run(host=os.environ.get('SERVER_HOST', '0.0.0.0'), port=int(os.environ.get('SERVER_PORT', 5005)))
