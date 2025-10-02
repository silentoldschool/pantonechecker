import os, uuid, re
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # CORS erlauben für Frontend
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL','sqlite:///pantone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------- Models -------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    api_token = db.Column(db.String(64), unique=True, index=True)
    role = db.Column(db.String(50), default='user')  # user / checker / admin

class ColorCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hex_color = db.Column(db.String(16), nullable=False)
    pantone = db.Column(db.String(64))
    notes = db.Column(db.Text)
    points = db.Column(db.String(200))  # CSV oder JSON
    status = db.Column(db.String(20), default='pending')  # pending / approved / rejected
    alternative_color = db.Column(db.String(16))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='checks')

# ------------------- Auth -------------------

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

# ------------------- Routes -------------------

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

# Neue Farbe einreichen (User)
@app.route('/colorchecks/request', methods=['POST'])
def request_color():
    data = request.get_json() or {}
    user = token_auth()
    pantone = data.get('pantone')
    points = data.get('points')  # CSV: TLW, KLB...
    notes = data.get('notes')
    
    # Format normalisieren: "P XXXX U/C"
    if pantone:
        pantone = pantone.upper().replace(" ", "")
        match = re.match(r"P(\d{3,4})([UC])", pantone)
        if match:
            pantone = f"P {match.group(1)} {match.group(2)}"
        else:
            return jsonify({'error': 'Pantone Format ungültig'}), 400

    cc = ColorCheck(
        pantone=pantone,
        hex_color=data.get('hex_color') or '#ffffff',  # default falls leer
        points=points,
        notes=notes,
        status='pending',
        user_id=user.id
    )
    db.session.add(cc)
    db.session.commit()
    return jsonify({'message': 'Color requested', 'id': cc.id})

# Alle Farben abrufen (für Admin/Checker)
@app.route('/colorchecks', methods=['GET'])
def list_checks():
    user = token_auth()
    if user.role in ['admin', 'checker']:
        entries = ColorCheck.query.all()
    else:
        entries = ColorCheck.query.filter_by(user_id=user.id).all()
    return jsonify([
        {
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'points': e.points,
            'status': e.status,
            'alternative_color': e.alternative_color,
            'notes': e.notes,
            'created_at': e.created_at.isoformat(),
            'user': e.user.username
        } for e in entries
    ])

# Pending Farben für Checker
@app.route('/colorchecks/pending', methods=['GET'])
def pending_checks():
    user = token_auth()
    if user.role not in ['admin', 'checker']:
        abort(403)
    entries = ColorCheck.query.filter_by(status='pending').all()
    return jsonify([
        {
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'points': e.points,
            'notes': e.notes,
            'user': e.user.username
        } for e in entries
    ])

# Freigeben / Ablehnen
@app.route('/colorchecks/<int:check_id>/approve', methods=['POST'])
def approve_check(check_id):
    user = token_auth()
    if user.role not in ['admin','checker']:
        abort(403)
    cc = ColorCheck.query.get_or_404(check_id)
    cc.status = 'approved'
    db.session.commit()
    return jsonify({'message': 'Color approved', 'id': cc.id})

@app.route('/colorchecks/<int:check_id>/reject', methods=['POST'])
def reject_check(check_id):
    user = token_auth()
    if user.role not in ['admin','checker']:
        abort(403)
    data = request.get_json() or {}
    cc = ColorCheck.query.get_or_404(check_id)
    cc.status = 'rejected'
    cc.alternative_color = data.get('alternative_color')
    db.session.commit()
    return jsonify({'message': 'Color rejected', 'id': cc.id})

# ------------------- User Verwaltung -------------------

@app.route('/users', methods=['GET'])
def list_users():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    return jsonify([{'id':u.id,'username':u.username,'role':u.role} for u in User.query.all()])

@app.route('/users', methods=['POST'])
def create_user():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    role = data.get('role','user')
    if not username or not password:
        return jsonify({'error':'username/password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error':'username exists'}), 400
    u = User(username=username, password_hash=generate_password_hash(password), role=role, api_token=uuid.uuid4().hex)
    db.session.add(u)
    db.session.commit()
    return jsonify({'id':u.id,'username':u.username,'role':u.role,'token':u.api_token})

# ------------------- Init -------------------

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
        print("Admin erstellt:", admin.username, "Token:", admin.api_token)

# ------------------- Frontend-Test -------------------

@app.route("/")
def index():
    return "PantoneChecker läuft erfolgreich 🚀"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
