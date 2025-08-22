#!/bin/bash
# Development server script for Bank API

echo "Starting Bank API development server..."

# Activate virtual environment
source venv/bin/activate

# Set development environment variables
export FLASK_ENV=development
export FLASK_DEBUG=true

# Start the Flask development server
python main.py
