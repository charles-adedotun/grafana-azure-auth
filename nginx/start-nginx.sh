#!/bin/bash
set -e

# Generate SSL certificate for cloud environment
generate_ssl_cert() {
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt \
    -subj "/CN=localhost"
}

# Update Nginx configuration
update_nginx_conf() {
    envsubst '${ROOT_URL} ${SERVER_NAME} ${NGINX_PORT}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf
}

# Generate SSL certificate only for cloud environment
if [ "$DEPLOYMENT" != "local" ]; then
    generate_ssl_cert
fi

# Initial configuration update
update_nginx_conf

# Start Nginx
nginx

# Function to safely reload Nginx
reload_nginx() {
    echo "Reloading Nginx configuration..."
    nginx -t && nginx -s reload
}

# Main loop to watch for configuration changes
while true; do
    if inotifywait -e modify,move,create,delete -q /etc/nginx/nginx.conf.template; then
        echo "Configuration template changed, updating Nginx configuration"
        if update_nginx_conf; then
            reload_nginx
        else
            echo "Failed to update Nginx configuration"
        fi
    fi
done