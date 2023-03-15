# Use a Node.js base image with version 14
FROM node:16

# Create a working directory in the container
WORKDIR /app

# Copy the server.js file from the local filesystem to the container
COPY ./server.js .

# Install any dependencies needed for the server
RUN npm lint

# Set the command to execute when the container starts
CMD ["node", "server.js"]