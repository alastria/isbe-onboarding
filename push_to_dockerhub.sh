#!/bin/bash

# A simple script to build and push a Docker image to Docker Hub.

# --- Configuration ---
# The name of the service in your docker compose.yml
SERVICE_NAME="certauth"
# The name of the image on Docker Hub
IMAGE_NAME="certauth"

# --- Script ---

# Ask for the Docker Hub username
read -p "Enter your Docker Hub username: " DOCKERHUB_USERNAME

# Check if username was entered
if [ -z "$DOCKERHUB_USERNAME" ]; then
    echo "Docker Hub username cannot be empty."
    exit 1
fi

# Define the full image tag
DOCKER_TAG="$DOCKERHUB_USERNAME/$IMAGE_NAME:latest"

echo "------------------------------------"
echo "Building the Docker image..."
echo "------------------------------------"
# Build the image using docker compose to ensure consistency
docker compose build $SERVICE_NAME

if [ $? -ne 0 ]; then
    echo "Docker build failed. Aborting."
    exit 1
fi

echo "------------------------------------"
echo "Tagging image as $DOCKER_TAG"
echo "------------------------------------"
# Docker compose builds the image with a default name like "isbetmf_isbetmf"
# We need to find that name and tag it. The name is usually <project>_<service>
docker tag isbetmf-isbetmf $DOCKER_TAG

if [ $? -ne 0 ]; then
    echo "Docker tag failed. Aborting."
    exit 1
fi

echo "------------------------------------"
echo "Pushing image to Docker Hub..."
echo "------------------------------------"
docker push $DOCKER_TAG

if [ $? -ne 0 ]; then
    echo "Docker push failed."
    exit 1
fi

echo "------------------------------------"
echo "Successfully pushed $DOCKER_TAG to Docker Hub."
echo "------------------------------------"
