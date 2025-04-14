import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash# type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash# type: ignore
from Crypto.Cipher import AES # type: ignore

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ============================
# Database Models
# ============================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # "user" or "admin"
    enc_key = db.Column(db.String(32), nullable=False)  # Each user gets an encryption key

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ============================
# Encryption Helper Functions (AES)
# ============================
def aes_encrypt(message, key_hex):
    key = bytes.fromhex(key_hex)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return f"{ciphertext.hex()}:{cipher.nonce.hex()}:{tag.hex()}"

def aes_decrypt(enc_str, key_hex):
    try:
        parts = enc_str.split(":")
        if len(parts) != 3:
            return "Invalid encrypted format"
        ciphertext, nonce, tag = parts
        key = bytes.fromhex(key_hex)
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(nonce))
        plaintext = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
        return plaintext.decode()
    except Exception as e:
        return f"Decryption error: {str(e)}"

# ============================
# Before First Request: Create Tables & Default Admin
# ============================
@app.before_first_request
def create_tables():
    db.create_all()
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            password=generate_password_hash("admin123"),
            role="admin",
            enc_key=os.urandom(16).hex()
        )
        db.session.add(admin)
        db.session.commit()

# ============================
# Routes
# ============================
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_view'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash("Login successful", "success")
            if user.role == 'admin':
                return redirect(url_for('admin_view'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role='user',
            enc_key=os.urandom(16).hex()
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    recipients = User.query.filter(User.id != current_user.id).all()
    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        message_text = request.form.get('message')
        if not receiver_id:
            flash("No recipient selected", "danger")
            return redirect(url_for('dashboard'))
        if not recipients:
            flash("No recipients available to send message", "danger")
            return redirect(url_for('dashboard'))
        receiver = User.query.get(receiver_id)
        encrypted_msg = aes_encrypt(message_text, receiver.enc_key)
        new_msg = Message(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            encrypted_message=encrypted_msg
        )
        db.session.add(new_msg)
        db.session.commit()
        flash("Message sent and encrypted successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', recipients=recipients)

@app.route('/my_messages')
def my_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    msgs = Message.query.filter_by(receiver_id=current_user.id).all()
    decrypted_msgs = []
    for msg in msgs:
        sender = User.query.get(msg.sender_id)
        plaintext = aes_decrypt(msg.encrypted_message, current_user.enc_key)
        decrypted_msgs.append({
            'sender': sender.username if sender else "Unknown",
            'message': plaintext,
            'timestamp': msg.timestamp
        })
    return render_template('my_messages.html', messages=decrypted_msgs)

@app.route('/admin', methods=['GET', 'POST'])
def admin_view():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST' and 'clear_messages' in request.form:
        # Clear all messages
        Message.query.delete()
        db.session.commit()
        flash("All messages have been cleared.", "success")
        return redirect(url_for('admin_view'))

    all_msgs = Message.query.all()
    msgs_info = []
    for msg in all_msgs:
        sender = User.query.get(msg.sender_id)
        receiver = User.query.get(msg.receiver_id)
        msgs_info.append({
            'sender': sender.username if sender else "Unknown",
            'receiver': receiver.username if receiver else "Unknown",
            'encrypted_message': msg.encrypted_message,
            'timestamp': msg.timestamp
        })
    users = User.query.filter(User.role != 'admin').all()
    return render_template('admin.html', messages=msgs_info, users=users)

@app.route('/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin_view'))  # Correct endpoint name
    if user.role == 'admin':
        flash("Cannot delete the admin user!", "danger")
        return redirect(url_for('admin_view'))  # Correct endpoint name
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for('admin_view'))  # Correct endpoint name


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
