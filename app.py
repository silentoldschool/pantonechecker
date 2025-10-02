import os, uuid, json
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///pantone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Beispiel: Pantone zu Hex
PANTONE_HEX = {
    "PANTONE 186 C": "#C8102E",
    "PANTONE 123 C": "#FFC72C",
    # weitere Pantone-Farben hier
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    api_token = db.Column(db.String(64), unique=True, index=True)
    role = db.Column(db.String(50), default='user')  # admin, reviewer, user

class ColorCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pantone = db.Column(db.String(64), nullable=False)
    hex_color = db.Column(db.String(16))
    notes = db.Column(db.Text)
    points = db.Column(db.Text)  # JSON-Array
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_points = db.Column(db.Text)  # JSON-Array
    alternative_color = db.Column(db.String(16))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id], backref='checks')
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

# Token Auth
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

# Login
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

# Neue Farbe als Anfrage
@app.route('/colorchecks/request', methods=['POST'])
def request_color():
    user = token_auth()
    data = request.get_json() or {}
    pantone = data.get('pantone')
    notes = data.get('notes', '')
    points = data.get('points', [])

    if not pantone:
        return jsonify({'error':'pantone required'}), 400

    hex_color = PANTONE_HEX.get(pantone)
    if not hex_color:
        return jsonify({'error':'unknown pantone'}), 400

    cc = ColorCheck(
        pantone=pantone,
        hex_color=hex_color,
        notes=notes,
        points=json.dumps(points),
        user_id=user.id,
        status='pending'
    )
    db.session.add(cc)
    db.session.commit()
    return jsonify({'id': cc.id, 'status': cc.status}), 201

# Liste aller Farben (nur freigegebene für normale User)
@app.route('/colorchecks', methods=['GET'])
def list_checks():
    user = token_auth()
    q = ColorCheck.query
    if user.role == 'user':
        q = q.filter_by(status='approved')
    entries = q.order_by(ColorCheck.created_at.desc()).limit(200).all()
    result = []
    for e in entries:
        result.append({
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'notes': e.notes,
            'points': json.loads(e.points or "[]"),
            'approved_points': json.loads(e.approved_points or "[]"),
            'alternative_color': e.alternative_color,
            'status': e.status,
            'user': e.user.username,
            'reviewer': e.reviewer.username if e.reviewer else None,
            'created_at': e.created_at.isoformat()
        })
    return jsonify(result)

# Ausstehende Farben für Review
@app.route('/colorchecks/pending', methods=['GET'])
def pending_colors():
    user = token_auth()
    if user.role not in ['admin', 'reviewer']:
        abort(403)
    entries = ColorCheck.query.filter_by(status='pending').all()
    return jsonify([
        {
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'notes': e.notes,
            'points': json.loads(e.points or "[]"),
            'user': e.user.username,
            'created_at': e.created_at.isoformat()
        } for e in entries
    ])

# Review / Freigabe
@app.route('/colorchecks/review/<int:color_id>', methods=['POST'])
def review_color(color_id):
    user = token_auth()
    if user.role not in ['admin', 'reviewer']:
        abort(403)
    data = request.get_json() or {}
    cc = ColorCheck.query.get_or_404(color_id)

    cc.status = data.get('status', cc.status)  # approved / rejected
    cc.approved_points = json.dumps(data.get('approved_points', []))
    cc.alternative_color = data.get('alternative_color')
    cc.reviewed_by = user.id

    db.session.commit()
    return jsonify({'id': cc.id, 'status': cc.status})

# User-Liste (nur für Admin)
@app.route('/users', methods=['GET'])
def list_users():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    users = User.query.all()
    return jsonify([{'id':u.id,'username':u.username,'role':u.role} for u in users])

# DB anlegen / Admin-User erstellen
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

# Index
@app.route("/")
def index():
    return "PantoneChecker läuft erfolgreich 🚀"

# Beispiel: Farben-Endpunkt
@app.route("/colors")
def colors():
    return {"status": "ok", "message": "Hier kommen später die Farben."}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
