import os, uuid
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL','sqlite:///pantone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    api_token = db.Column(db.String(64), unique=True, index=True)
    role = db.Column(db.String(50), default='user')

class ColorCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pantone = db.Column(db.String(64))
    hex_color = db.Column(db.String(16), nullable=False)
    notes = db.Column(db.Text)
    points = db.Column(db.String(256))  # z.B. "Testliner weiß, Kraftliner braun"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='checks')

# --- Pantone → Hex Mapping ---
pantone_to_hex = {
    "Pantone 186 C": "#C8102E",
    "Pantone 123 C": "#FFC600",
    "Pantone 280 C": "#012169",
    "Pantone 356 C": "#009639",
    "Pantone 7541 C": "#D9D9D6"
}

# --- Auth ---
def token_auth():
    token = request.headers.get('X-API-TOKEN') or request.headers.get('Authorization')
    if token and token.startswith('Token '):
        token = token.split(' ',1)[1]
    if not token:
        abort(401, 'token missing')
    user = User.query.filter_by(api_token=token).first()
    if not user:
        abort(401, 'invalid token')
    return user

# --- Routes ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error':'username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error':'invalid credentials'}), 401
    if not user.api_token:
        user.api_token = uuid.uuid4().hex
        db.session.commit()
    return jsonify({'token': user.api_token, 'role': user.role})

# --- ColorChecks ---
@app.route('/colorchecks', methods=['POST'])
def add_check():
    user = token_auth()
    data = request.get_json() or {}
    pantone = data.get('pantone')
    hex_color = data.get('hex_color')
    notes = data.get('notes')
    points = data.get('points')

    # Auto Hex
    if pantone and not hex_color:
        hex_color = pantone_to_hex.get(pantone)
        if not hex_color:
            return jsonify({'error': 'Pantone unbekannt, bitte Hex manuell angeben'}), 400
    if not hex_color:
        return jsonify({'error':'hex_color required'}), 400

    cc = ColorCheck(pantone=pantone, hex_color=hex_color, notes=notes, points=points, user_id=user.id)
    db.session.add(cc)
    db.session.commit()
    return jsonify({'id': cc.id, 'created_at': cc.created_at.isoformat()}), 201

@app.route('/colorchecks', methods=['GET'])
def list_checks():
    user = token_auth()
    q = ColorCheck.query
    if user.role != 'admin':
        q = q.filter_by(user_id=user.id)
    entries = q.order_by(ColorCheck.created_at.desc()).limit(200).all()
    result = []
    for e in entries:
        result.append({
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'notes': e.notes,
            'points': e.points,
            'created_at': e.created_at.isoformat(),
            'user': e.user.username
        })
    return jsonify(result)

# --- Userverwaltung ---
@app.route('/users', methods=['GET'])
def list_users():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    users = User.query.all()
    return jsonify([{'id':u.id,'username':u.username,'role':u.role} for u in users])

@app.route('/users', methods=['POST'])
def add_user():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    if not username or not password:
        return jsonify({'error':'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error':'username exists'}), 400
    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        api_token=uuid.uuid4().hex
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'id': new_user.id, 'username': new_user.username, 'role': new_user.role, 'token': new_user.api_token}), 201

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    target = User.query.get_or_404(user_id)
    db.session.delete(target)
    db.session.commit()
    return jsonify({'message':'user deleted'})

# --- Init DB & Admin ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password_hash=generate_password_hash("admin123"),
            api_token=uuid.uuid4().hex,
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin-User erstellt:", admin.username, "Token:", admin.api_token)

# --- Start ---
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
