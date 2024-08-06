#!/bin/bash
set -e

# Replace the ROOT_URL placeholder in the Nginx config
envsubst '${ROOT_URL}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start Nginx
exec nginx -g 'daemon off;'