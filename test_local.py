#!/usr/bin/env python3
"""
Simple test script to verify the BankAPI Flask application works locally
"""

import requests
import json

def test_app():
    base_url = "http://localhost:8000"
    
    print("Testing BankAPI endpoints...")
    
    # Test login endpoint
    try:
        response = requests.post(f"{base_url}/api/v1/login", 
                               json={"username": "test", "password": "test"})
        print(f"Login test: {response.status_code}")
        if response.status_code == 200:
            print(f"Token: {response.json().get('access_token', 'No token')[:50]}...")
    except Exception as e:
        print(f"Login test failed: {e}")
    
    # Test account endpoint
    try:
        response = requests.get(f"{base_url}/api/v1/accounts/12345")
        print(f"Account test: {response.status_code}")
        if response.status_code == 200:
            print(f"Account data: {response.json()}")
    except Exception as e:
        print(f"Account test failed: {e}")
    
    # Test comment endpoint
    try:
        response = requests.post(f"{base_url}/api/v1/comment", 
                               json={"comment": "Test comment"})
        print(f"Comment test: {response.status_code}")
        if response.status_code == 200:
            print(f"Comment response: {response.json()}")
    except Exception as e:
        print(f"Comment test failed: {e}")

if __name__ == "__main__":
    test_app() 