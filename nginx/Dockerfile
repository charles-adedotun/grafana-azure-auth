FROM nginx:latest

# Install OpenSSL
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Set up SSL directory
RUN mkdir -p /etc/nginx/ssl

# Set default value for ROOT_URL
ARG ROOT_URL=localhost

# Generate self-signed certificate with sanitized Common Name
RUN SANITIZED_CN=$(echo "$ROOT_URL" | sed -e 's/^https*:\/\///' -e 's/:.*//' -e 's/[^a-zA-Z0-9.-]/-/g') && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=${SANITIZED_CN}" && \
    echo "Generated SSL certificate for CN: ${SANITIZED_CN}"

# Copy the template Nginx config file
COPY nginx.conf.template /etc/nginx/nginx.conf.template

# Copy the start script
COPY start-nginx.sh /start-nginx.sh

# Make the start script executable
RUN chmod +x /start-nginx.sh

EXPOSE 443
EXPOSE 80

# Set the start script as the entry point
CMD ["/start-nginx.sh"]