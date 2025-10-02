import sys, uuid
from werkzeug.security import generate_password_hash
from app import db, User

def create(username, password, role='admin'):
    if User.query.filter_by(username=username).first():
        print('User exists')
        return
    u = User(username=username, password_hash=generate_password_hash(password), role=role)
    u.api_token = uuid.uuid4().hex
    db.session.add(u)
    db.session.commit()
    print('Created user:', username)
    print('API token:', u.api_token)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_user.py USERNAME PASSWORD [role]")
    else:
        create(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv)>3 else 'admin')
