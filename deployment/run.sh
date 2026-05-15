#!/bin/bash
# SecureShield Quick Start Script

echo "Starting SecureShield..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker first."
    exit 1
fi

# Start the services
echo "Building and starting containers..."
docker-compose up -d --build

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "======================================"
    echo "SecureShield is running!"
    echo "======================================"
    echo ""
    echo "Frontend:  http://localhost:3000"
    echo "Backend:   http://localhost:8000"
    echo "API Docs:  http://localhost:8000/api/v1/docs"
    echo ""
    echo "Default Admin Credentials:"
    echo "  Username: admin"
    echo "  Password: Admin123!"
    echo ""
    echo "======================================"
else
    echo "Some services failed to start. Check logs with:"
    echo "docker-compose logs"
fi