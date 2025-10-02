import os
import uuid
import re
from datetime import datetime
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

# --- Flask App ---
app = Flask(__name__)
CORS(app)  # <-- erlaubt CORS für alle Origins
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///pantone.db')
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
    pantone = db.Column(db.String(16), nullable=False)
    hex_color = db.Column(db.String(16))
    notes = db.Column(db.Text)
    points = db.Column(db.String(256))  # Comma-separated: Testliner weiß,Kraftliner braun...
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='checks')
    alt_hex = db.Column(db.String(16))  # Optional: Alternativfarbe

# --- Token Auth ---
def token_auth():
    token = request.headers.get('X-API-TOKEN') or request.headers.get('Authorization')
    if token and token.startswith('Token '):
        token = token.split(' ', 1)[1]
    if not token:
        abort(401, 'token missing')
    user = User.query.filter_by(api_token=token).first()
    if not user:
        abort(401, 'invalid token')
    return user

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'invalid credentials'}), 401
    if not user.api_token:
        user.api_token = uuid.uuid4().hex
        db.session.commit()
    return jsonify({'token': user.api_token})

# --- List Colors ---
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
            'alt_hex': e.alt_hex,
            'notes': e.notes,
            'points': e.points.split(',') if e.points else [],
            'approved': e.approved,
            'created_at': e.created_at.isoformat(),
            'user': e.user.username
        })
    return jsonify(result)

# --- Request New Color ---
@app.route('/colorchecks/request', methods=['POST'])
def request_color():
    user = token_auth()
    data = request.get_json()
    if not data:
        return jsonify({'error': 'kein JSON erhalten'}), 400

    pantone_raw = data.get('pantone')
    notes = data.get('notes')
    points = data.get('points', [])

    if not pantone_raw:
        return jsonify({'error': 'pantone required'}), 400

    # Fehlertoleranz: P XXXX C / P XXXX U
    match = re.match(r'P\s*0*(\d+)\s*([CUcu])', pantone_raw.replace(' ', ''))
    if not match:
        return jsonify({'error': 'pantone format invalid'}), 400
    pantone = f"P {int(match.group(1)):04d} {match.group(2).upper()}"

    # Optional: Hex automatisch bestimmen (hier Beispiel: nur zufällig oder Lookup)
    hex_color = data.get('hex_color') or f"#{uuid.uuid4().hex[:6]}"

    cc = ColorCheck(
        pantone=pantone,
        hex_color=hex_color,
        notes=notes,
        points=','.join(points),
        user_id=user.id,
        approved=False
    )
    db.session.add(cc)
    db.session.commit()

    return jsonify({'id': cc.id, 'pantone': cc.pantone, 'hex_color': cc.hex_color, 'points': points}), 201

# --- Approve Color (Admin) ---
@app.route('/colorchecks/approve/<int:color_id>', methods=['POST'])
def approve_color(color_id):
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    cc = ColorCheck.query.get_or_404(color_id)
    cc.approved = True
    cc.alt_hex = request.json.get('alt_hex')
    db.session.commit()
    return jsonify({'status': 'approved', 'id': cc.id})

# --- User Management ---
@app.route('/users', methods=['GET'])
def list_users():
    user = token_auth()
    if user.role != 'admin':
        abort(403)
    users = User.query.all()
    return jsonify([{'id': u.id, 'username': u.username, 'role': u.role, 'token': u.api_token} for u in users])

# --- Index ---
@app.route("/")
def index():
    return "PantoneChecker läuft erfolgreich 🚀"

# --- Colors Endpoint ---
@app.route("/colors")
def colors():
    return {"status": "ok", "message": "Hier kommen später die Farben."}

# --- DB Init ---
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

# --- Run ---
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
