import os, uuid, re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///pantone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), default='user')

class ColorCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pantone = db.Column(db.String(16), nullable=False)
    hex_color = db.Column(db.String(16))
    points = db.Column(db.String(256))  # CSV
    approved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='checks')

# ---------------- Pantone Normalisierung ----------------
def normalize_pantone(value):
    """
    Wandelt Eingaben wie 'p186u', 'P 0186 U' etc. in das Format 'P 0186 U' um
    """
    match = re.match(r'P\s*0*(\d+)\s*([UCuc])', value.replace(' ', ''), re.I)
    if match:
        number, suffix = match.groups()
        return f"P {int(number):04d} {suffix.upper()}"
    return value.upper()

# ---------------- Endpoints ----------------

@app.route('/colorchecks', methods=['GET'])
def list_checks():
    entries = ColorCheck.query.order_by(ColorCheck.created_at.desc()).limit(200).all()
    result = []
    for e in entries:
        result.append({
            'id': e.id,
            'pantone': e.pantone,
            'hex_color': e.hex_color,
            'points': e.points.split(',') if e.points else [],
            'approved': e.approved,
            'notes': e.notes,
            'user': e.user.username
        })
    return jsonify(result)

@app.route('/colorchecks/request', methods=['POST'])
def request_color():
    data = request.get_json() or {}
    pantone_raw = data.get('pantone')
    notes = data.get('notes')
    points_list = data.get('points') or []

    if not pantone_raw:
        return jsonify({'error': 'Pantone erforderlich'}), 400

    pantone_norm = normalize_pantone(pantone_raw)

    # Default user=admin (für Demo)
    user = User.query.filter_by(username='admin').first()
    if not user:
        return jsonify({'error': 'Kein User gefunden'}), 400

    cc = ColorCheck(
        pantone=pantone_norm,
        points=','.join(points_list),
        notes=notes,
        user_id=user.id
    )
    db.session.add(cc)
    db.session.commit()
    return jsonify({'id': cc.id, 'pantone': cc.pantone})

@app.route('/colorchecks/approve/<int:id>', methods=['POST'])
def approve_color(id):
    cc = ColorCheck.query.get_or_404(id)
    cc.approved = True
    db.session.commit()
    return jsonify({'status': 'ok'})

# ---------------- Admin User anlegen ----------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password_hash=generate_password_hash("admin123"),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin-User erstellt:", admin.username)

# ---------------- Test Endpoint ----------------
@app.route("/")
def index():
    return "PantoneChecker läuft erfolgreich 🚀"

@app.route("/colors")
def colors():
    return {"status": "ok", "message": "Hier kommen später die Farben."}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
