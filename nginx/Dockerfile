# Use the official Nginx image from the Docker Hub
FROM nginx:alpine

# Copy your custom Nginx configuration (if needed)
COPY nginx.conf /etc/nginx/nginx.conf

# Copy your static website files to the Nginx web root
COPY ./www /usr/share/nginx/html

# Expose port 80 to the outside world
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
