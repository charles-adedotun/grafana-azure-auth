FROM nginx:latest

# Copy the template Nginx config file
COPY nginx.conf.template /etc/nginx/nginx.conf.template

# Copy the start script
COPY start-nginx.sh /start-nginx.sh

# Make the start script executable
RUN chmod +x /start-nginx.sh

# Set the start script as the entry point
CMD ["/start-nginx.sh"]