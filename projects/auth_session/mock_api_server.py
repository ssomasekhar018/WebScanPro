#!/usr/bin/env python3
"""
Mock API Server for IDOR Testing
Simulates vulnerable and secure endpoints for IDOR detection system testing.
"""

from flask import Flask, request, jsonify
import json
import time
import random
from datetime import datetime

app = Flask(__name__)

# Mock user data with potential IDOR vulnerabilities
MOCK_USERS = {
    "101": {
        "id": "101",
        "username": "john_doe",
        "email": "john@example.com",
        "phone": "555-0101",
        "profile": {
            "name": "John Doe",
            "address": "123 Main St",
            "ssn": "123-45-6789"
        }
    },
    "102": {
        "id": "102", 
        "username": "jane_smith",
        "email": "jane@example.com",
        "phone": "555-0102",
        "profile": {
            "name": "Jane Smith",
            "address": "456 Oak Ave",
            "ssn": "987-65-4321"
        }
    },
    "103": {
        "id": "103",
        "username": "bob_johnson",
        "email": "bob@example.com",
        "phone": "555-0103",
        "profile": {
            "name": "Bob Johnson",
            "address": "789 Pine Rd",
            "ssn": "456-78-9012"
        }
    }
}

# Mock documents/invoices data
MOCK_DOCUMENTS = {
    "201": {"id": "201", "user_id": "101", "title": "John's Tax Document", "content": "Tax return 2023", "sensitive": True},
    "202": {"id": "202", "user_id": "102", "title": "Jane's Medical Report", "content": "Annual physical results", "sensitive": True},
    "203": {"id": "203", "user_id": "103", "title": "Bob's Contract", "content": "Employment agreement", "sensitive": True},
    "301": {"id": "301", "user_id": "101", "title": "John's Invoice", "amount": 150.00, "status": "paid"},
    "302": {"id": "302", "user_id": "102", "title": "Jane's Invoice", "amount": 275.50, "status": "pending"},
    "303": {"id": "303", "user_id": "103", "title": "Bob's Invoice", "amount": 89.99, "status": "paid"}
}

# Mock orders data
MOCK_ORDERS = {
    "401": {"id": "401", "user_id": "101", "product": "Laptop", "status": "delivered", "total": 999.99},
    "402": {"id": "402", "user_id": "102", "product": "Phone", "status": "shipped", "total": 699.99},
    "403": {"id": "403", "user_id": "103", "product": "Tablet", "status": "processing", "total": 399.99}
}

def validate_token(auth_header):
    """Mock token validation - extract user ID from token."""
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    # Mock token parsing - in real implementation, this would validate JWT
    if 'user_id":"101"' in token:
        return "101"
    elif 'user_id":"102"' in token:
        return "102"
    elif 'user_id":"103"' in token:
        return "103"
    
    return None

def simulate_idor_vulnerability():
    """Randomly simulate IDOR vulnerabilities for testing."""
    # 30% chance of allowing unauthorized access (simulating vulnerable endpoint)
    return random.random() < 0.3

@app.route('/')
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "endpoints": [
            "/user/profile",
            "/api/user/<id>/details", 
            "/profile",
            "/invoice",
            "/order/<id>/status",
            "/document",
            "/api/account/<id>/balance",
            "/settings",
            "/messages/<id>/view",
            "/report"
        ]
    })

# VULNERABLE ENDPOINTS (simulate IDOR vulnerabilities)

@app.route('/user/profile')
def user_profile():
    """VULNERABLE: User profile endpoint with IDOR vulnerability."""
    user_id = request.args.get('user_id', request.args.get('id', request.args.get('uid')))
    
    # Add artificial delay
    time.sleep(random.uniform(0.01, 0.05))
    
    if not user_id:
        return jsonify({"error": "User ID required"}), 400
    
    # VULNERABLE: No proper authorization check
    if user_id in MOCK_USERS:
        return jsonify(MOCK_USERS[user_id]), 200
    
    return jsonify({"error": "User not found"}), 404

@app.route('/profile')
def profile():
    """VULNERABLE: Profile endpoint with IDOR vulnerability."""
    uid = request.args.get('uid', request.args.get('id', request.args.get('user_id')))
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not uid:
        return jsonify({"error": "User ID required"}), 400
    
    # VULNERABLE: No authorization check
    if uid in MOCK_USERS:
        user_data = MOCK_USERS[uid].copy()
        # Return only profile section
        return jsonify(user_data.get('profile', {})), 200
    
    return jsonify({"error": "Profile not found"}), 404

@app.route('/invoice')
def invoice():
    """VULNERABLE: Invoice endpoint with IDOR vulnerability."""
    invoice_id = request.args.get('id', request.args.get('invoice_id'))
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not invoice_id:
        return jsonify({"error": "Invoice ID required"}), 400
    
    # VULNERABLE: No authorization check
    for doc_id, doc_data in MOCK_DOCUMENTS.items():
        if doc_data.get('amount') and str(doc_data['id']) == invoice_id:
            return jsonify(doc_data), 200
    
    return jsonify({"error": "Invoice not found"}), 404

@app.route('/document')
def document():
    """VULNERABLE: Document endpoint with IDOR vulnerability."""
    doc_id = request.args.get('doc_id', request.args.get('id'))
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not doc_id:
        return jsonify({"error": "Document ID required"}), 400
    
    # VULNERABLE: No authorization check
    if doc_id in MOCK_DOCUMENTS:
        return jsonify(MOCK_DOCUMENTS[doc_id]), 200
    
    return jsonify({"error": "Document not found"}), 404

@app.route('/report')
def report():
    """VULNERABLE: Report endpoint with IDOR vulnerability."""
    report_id = request.args.get('report_id', request.args.get('id'))
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not report_id:
        return jsonify({"error": "Report ID required"}), 400
    
    # VULNERABLE: No authorization check
    # Simulate different types of reports
    if report_id in ["101", "102", "103"]:
        return jsonify({
            "report_id": report_id,
            "title": f"User Activity Report {report_id}",
            "generated_at": datetime.now().isoformat(),
            "data": {
                "login_count": random.randint(1, 50),
                "page_views": random.randint(100, 1000),
                "last_activity": datetime.now().isoformat()
            }
        }), 200
    
    return jsonify({"error": "Report not found"}), 404

# SECURE ENDPOINTS (proper authorization checks)

@app.route('/api/user/<user_id>/details')
def api_user_details(user_id):
    """SECURE: User details with proper authorization."""
    auth_header = request.headers.get('Authorization')
    current_user_id = validate_token(auth_header)
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # SECURE: Check if user is accessing their own data
    if current_user_id != user_id:
        return jsonify({"error": "Forbidden - Access denied"}), 403
    
    if user_id in MOCK_USERS:
        return jsonify(MOCK_USERS[user_id]), 200
    
    return jsonify({"error": "User not found"}), 404

@app.route('/order/<order_id>/status')
def order_status(order_id):
    """SECURE: Order status with proper authorization."""
    auth_header = request.headers.get('Authorization')
    current_user_id = validate_token(auth_header)
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # SECURE: Check if order belongs to current user
    if order_id in MOCK_ORDERS:
        order_data = MOCK_ORDERS[order_id]
        if order_data['user_id'] == current_user_id:
            return jsonify(order_data), 200
        else:
            return jsonify({"error": "Forbidden - Order does not belong to you"}), 403
    
    return jsonify({"error": "Order not found"}), 404

@app.route('/api/account/<account_id>/balance')
def account_balance(account_id):
    """SECURE: Account balance with proper authorization."""
    auth_header = request.headers.get('Authorization')
    current_user_id = validate_token(auth_header)
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # SECURE: Account ID should match user ID
    if account_id != current_user_id:
        return jsonify({"error": "Forbidden - Invalid account access"}), 403
    
    # Return mock balance data
    return jsonify({
        "account_id": account_id,
        "balance": round(random.uniform(100.00, 10000.00), 2),
        "currency": "USD",
        "last_updated": datetime.now().isoformat()
    }), 200

@app.route('/settings')
def settings():
    """SECURE: User settings with proper authorization."""
    auth_header = request.headers.get('Authorization')
    current_user_id = validate_token(auth_header)
    user_id = request.args.get('user_id')
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    if not user_id:
        return jsonify({"error": "User ID required"}), 400
    
    # SECURE: Settings can only be accessed by the owner
    if current_user_id != user_id:
        return jsonify({"error": "Forbidden - Cannot access other users' settings"}), 403
    
    if user_id in MOCK_USERS:
        return jsonify({
            "user_id": user_id,
            "theme": "dark",
            "notifications": True,
            "privacy_level": "high",
            "language": "en"
        }), 200
    
    return jsonify({"error": "User settings not found"}), 404

@app.route('/messages/<message_id>/view')
def view_message(message_id):
    """SECURE: Message viewing with proper authorization."""
    auth_header = request.headers.get('Authorization')
    current_user_id = validate_token(auth_header)
    
    time.sleep(random.uniform(0.01, 0.05))
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # SECURE: Simulate message ownership check
    # In real implementation, check if message belongs to current user
    if message_id.endswith(current_user_id):
        return jsonify({
            "message_id": message_id,
            "from": "system@example.com",
            "subject": "Important Update",
            "content": "This is a secure message for user " + current_user_id,
            "timestamp": datetime.now().isoformat()
        }), 200
    else:
        return jsonify({"error": "Forbidden - Message not accessible"}), 403

# Additional endpoints with mixed security

@app.route('/api/secure/user/<user_id>')
def api_secure_user(user_id):
    """Secure user endpoint with proper checks."""
    auth_header = request.headers.get('Authorization')
    current_user_id = validate_token(auth_header)
    
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    if current_user_id != user_id:
        return jsonify({"error": "Forbidden"}), 403
    
    if user_id in MOCK_USERS:
        return jsonify(MOCK_USERS[user_id]), 200
    
    return jsonify({"error": "Not found"}), 404

@app.route('/api/vulnerable/user/<user_id>')
def api_vulnerable_user(user_id):
    """Vulnerable user endpoint - no proper checks."""
    time.sleep(random.uniform(0.01, 0.05))
    
    # VULNERABLE: No authentication or authorization
    if user_id in MOCK_USERS:
        return jsonify(MOCK_USERS[user_id]), 200
    
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    print("Starting Mock API Server for IDOR Testing...")
    print("Available endpoints:")
    print("- Vulnerable endpoints: /user/profile, /profile, /invoice, /document, /report")
    print("- Secure endpoints: /api/user/<id>/details, /order/<id>/status, /api/account/<id>/balance")
    print("- Mixed endpoints: /settings, /messages/<id>/view")
    print("\nServer starting on port 5002...")
    
    app.run(host='0.0.0.0', port=5002, debug=False)