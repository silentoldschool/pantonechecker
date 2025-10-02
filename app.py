import os, uuid, re
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Erlaubt Cross-Origin Requests
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL','sqlite:///pantone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ===========================
# Datenbank-Modelle
# ===========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    api_token = db.Column(db.String(64), unique=True, index=True)
    role = db.Column(db.String(50), default='user')

class ColorCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hex_color = db.Column(db.String(16), nullable=False)
    pantone = db.Column(db.String(64))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='checks')
    points = db.relationship('ColorPoint', backref='color', cascade="all, delete-orphan")

class ColorPoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    color_id = db.Column(db.Integer, db.ForeignKey('color_check.id'), nullable=False)

# ===========================
# Hilfsfunktionen
# ===========================

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

# Beispiel: Mapping Pantone -> Hex
pantone_map = {
    "P 0186 U": "#FEE0E0",
    "P 186 C": "#D91F26",
    "P 1234 U": "#FFCC00",
}
def pantone_to_hex(pantone):
    return pantone_map.get(pantone, "#FFFFFF")  # Weiß als Default

# ===========================
# Routes
# ===========================

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
    return jsonify({'token': user.api_token})

@app.route('/colorchecks/request', methods=['POST'])
def request_color():
    user = token_auth()
    data = request.get_json() or {}
    pantone_raw = data.get('pantone')
    points = data.get('points', [])

    if not pantone_raw:
        return jsonify({'error':'pantone required'}), 400

    # Fehlertoleranz: z.B. P186u -> P 0186 U
    match = re.match(r'P\s*(\d{1,4})\s*([UCuc])', pantone_raw.replace(' ','').upper())
    if not match:
        return jsonify({'error':'invalid pantone format'}), 400
    number, suffix = match.groups()
    pantone = f'P {int(number):04d} {suffix}'

    hex_color = pantone_to_hex(pantone)

    color_check = ColorCheck(
        hex_color=hex_color,
        pantone=pantone,
        user_id=user.id
    )
    db.session.add(color_check)
    db.session.commit()

    for p in points:
        cp = ColorPoint(name=p, color_id=color_check.id)
        db.session.add(cp)
    db.session.commit()

    return jsonify({
        'id': color_check.id,
        'pantone': pantone,
        'hex_color': hex_color,
        'points': points
    }), 201

@app.route('/colorchecks', methods=['GET'])
def list_checks():
    user = token_auth()
    q = ColorCheck.query
    if user.role != 'admin':
        q = q.filter_by(user_id=user.id)
    entries = q.order_by(ColorCheck.created_at.desc()).all()
    result = []
    for e in entries:
        result.append({
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'notes': e.notes,
            'created_at': e.created_at.isoformat(),
            'user': e.user.username,
            'points': [p.name for p in e.points]
        })
    return jsonify(result)

@app.route('/users', methods=['GET'])
def list_users():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    users = User.query.all()
    return jsonify([{'id':u.id,'username':u.username,'role':u.role} for u in users])

@app.route("/")
def index():
    return "PantoneChecker läuft erfolgreich 🚀"

# ===========================
# Datenbank anlegen
# ===========================

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

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
