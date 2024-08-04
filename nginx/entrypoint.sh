#!/bin/sh
# Entrypoint script for Nginx container

# Start Nginx
exec nginx -g 'daemon off;'
