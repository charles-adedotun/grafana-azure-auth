FROM nginx:latest

# Install inotify-tools
RUN apt-get update && \
    apt-get install -y inotify-tools && \
    rm -rf /var/lib/apt/lists/*

# Set default values
ARG DEPLOYMENT=local

# Copy the appropriate Nginx config template
COPY nginx.${DEPLOYMENT}.conf.template /etc/nginx/nginx.conf.template

# Copy the start script
COPY start-nginx.sh /start-nginx.sh

# Make the start script executable
RUN chmod +x /start-nginx.sh

EXPOSE 3200 80 443

# Set the start script as the entry point
CMD ["/start-nginx.sh"]