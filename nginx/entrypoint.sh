#!/bin/sh
set -e

# Substitute environment variables in the Nginx configuration
envsubst '${AZURE_TENANT} ${AZURE_CLIENT_ID} ${AZURE_POLICY_NAME}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Execute the CMD
exec "$@"
