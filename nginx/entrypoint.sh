#!/bin/sh
# Entrypoint script for Nginx container

# Replace environment variables in Nginx config
envsubst '$$HOSTNAME' < /etc/nginx/nginx.conf > /etc/nginx/nginx.conf

# Start Nginx
exec nginx -g 'daemon off;'
