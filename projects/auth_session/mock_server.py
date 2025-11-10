from flask import Flask, jsonify, request
import random

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    """Mock login endpoint that simulates success or failure."""
    # Simulate a 25% success rate
    if random.random() < 0.25:
        response = {
            'status_code': 200,
            'auth_result': 'success',
            'session_id': 'mock_session_id_12345'
        }
        return jsonify(response), 200
    else:
        response = {
            'status_code': 401,
            'auth_result': 'failure',
            'failure_reason': 'wrong password'
        }
        return jsonify(response), 401


# In-memory database of users and their resources
users = {
    "user_a": {"owned_resources": ["101", "102"]},
    "user_b": {"owned_resources": ["201", "202"]}
}

@app.route('/user/profile', methods=['GET'])
def get_user_profile():
    """Simulates fetching a user profile, vulnerable to IDOR."""
    user_id = request.headers.get('X-User-ID')
    profile_id = request.args.get('id')

    if not user_id or not profile_id:
        return jsonify({"error": "User ID and profile ID are required"}), 400

    # IDOR vulnerability: No check to see if user_id has access to profile_id
    return jsonify({
        "profile_id": profile_id,
        "data": f"This is the profile data for ID {profile_id}"
    }), 200

if __name__ == '__main__':
    app.run(port=5000)

