from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import os  # <-- for environment variables

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this!
jwt = JWTManager(app)

# In-memory storage (replace with a database in production)
users = {}
messages = []
connected_users = {}

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    if not all(k in data for k in ('name', 'email', 'password')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['email'] in users:
        return jsonify({'error': 'Email already registered'}), 400
    
    user_id = str(uuid.uuid4())
    users[data['email']] = {
        'id': user_id,
        'name': data['name'],
        'email': data['email'],
        'password': generate_password_hash(data['password']),
        'status': 'offline'
    }
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = users.get(data['email'])
    
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    access_token = create_access_token(identity=user['id'])
    users[data['email']]['status'] = 'online'
    
    return jsonify({'token': access_token}), 200

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    user_list = [
        {
            'id': user['id'],
            'name': user['name'],
            'email': email,
            'status': user['status']
        }
        for email, user in users.items()
        if user['id'] != current_user_id
    ]
    return jsonify({'users': user_list})

@app.route('/api/messages/<receiver_id>', methods=['GET'])
@jwt_required()
def get_messages(receiver_id):
    current_user_id = get_jwt_identity()
    user_messages = [
        msg for msg in messages
        if (msg['senderId'] == current_user_id and msg['receiverId'] == receiver_id) or
           (msg['senderId'] == receiver_id and msg['receiverId'] == current_user_id)
    ]
    return jsonify({'messages': user_messages})

@socketio.on('connect')
def handle_connect():
    user_id = request.args.get('user_id')
    if user_id:
        connected_users[user_id] = request.sid
        emit('status', {'userId': user_id, 'status': 'online'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    for user_id, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[user_id]
            emit('status', {'userId': user_id, 'status': 'offline'}, broadcast=True)
            break

@socketio.on('message')
def handle_message(data):
    sender_id = request.args.get('user_id')
    message = {
        'id': str(uuid.uuid4()),
        'content': data['content'],
        'senderId': sender_id,
        'receiverId': data['receiverId'],
        'timestamp': datetime.now().isoformat()
    }
    messages.append(message)
    
    receiver_sid = connected_users.get(data['receiverId'])
    if receiver_sid:
        emit('message', message, room=receiver_sid)
    emit('message', message, room=request.sid)

@socketio.on('typing')
def handle_typing(data):
    receiver_sid = connected_users.get(data['receiverId'])
    if receiver_sid:
        emit('typing', {
            'userId': request.args.get('user_id'),
            'isTyping': data['isTyping']
        }, room=receiver_sid)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # <-- use host-assigned port if available
    print(f"Starting server on port {port}")
    socketio.run(app, debug=True, host='0.0.0.0', port=port)
