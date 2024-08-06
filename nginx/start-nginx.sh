#!/bin/bash
set -e

# Replace environment variables in the Nginx config template
envsubst '${ROOT_URL}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start Nginx
exec nginx -g 'daemon off;'