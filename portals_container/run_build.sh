#!/usr/bin/env bash

# Variables
IMAGE_NAME="bull_portals"
DOCKERFILE="DockerFile"
HOST_DIR="/tmp/par.dat"
CONTAINER_DIR="/app/par.dat"
PARALLAX_DIR="../../parallax"

echo "Creating and allocating file: $HOST_FILE"
fallocate -l 10G $"$HOST_DIR"

echo "Building Docker image..."
docker build -t $IMAGE_NAME -f $DOCKERFILE .

echo "Running Docker container..."
CONTAINER_ID=$(docker run -it -d --privileged --network host -v "$HOST_DIR":"$CONTAINER_DIR" $IMAGE_NAME)

sleep 1

# Copy the parallax directory into the running container
echo "Copying parallax directory and cmake command into the container..."
docker cp "$PARALLAX_DIR" "$CONTAINER_ID":/app/

docker exec -it "$CONTAINER_ID" /bin/bash
