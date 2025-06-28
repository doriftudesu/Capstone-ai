# --- DEBUG STARTUP CHECK ---
print("DEBUG: app.py script started execution (1).")
# --- END DEBUG STARTUP CHECK ---

from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import timedelta

print("DEBUG: All imports successful (2).")

# --- SECRET_KEY Management ---
SECRET_KEY_FILE = 'secret_key.txt'
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        APP_SECRET_KEY = f.read().strip()
    print(f"DEBUG: SECRET_KEY loaded from {SECRET_KEY_FILE}.")
else:
    APP_SECRET_KEY = os.urandom(24).hex()
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(APP_SECRET_KEY)
    print(f"DEBUG: NEW SECRET_KEY generated and saved to {SECRET_KEY_FILE}.")

# --- App Config ---
app = Flask(__name__)
app.config.update(
    SECRET_KEY=APP_SECRET_KEY,
    SQLALCHEMY_DATABASE_URI="sqlite:///site.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,  # Recommended to disable
    UPLOAD_FOLDER="uploads/",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    # Session settings
    SESSION_COOKIE_PERMANENT=False,
    SESSION_REFRESH_EACH_REQUEST=True,
    SESSION_COOKIE_HTTPONLY=True,  # Security: prevent XSS access to cookies
    SESSION_COOKIE_SECURE=False,   # Set to True in production with HTTPS
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    # Remember me settings
    REMEMBER_COOKIE_DURATION=timedelta(days=30),
    REMEMBER_COOKIE_NAME='remember_token',
    REMEMBER_COOKIE_HTTPONLY=True,  # Security enhancement
    REMEMBER_COOKIE_SECURE=False,   # Set to True in production with HTTPS
)

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

print("DEBUG: App configuration loaded (3).")

db = SQLAlchemy(app)
print("DEBUG: SQLAlchemy initialized (5).")

socketio = SocketIO(app, cors_allowed_origins="*")  # Configure CORS as needed
print("DEBUG: SocketIO initialized (6).")

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"
print("DEBUG: LoginManager initialized (7).")

# --- User Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # Keep old password column for backward compatibility
    password = db.Column(db.String(150), nullable=True)  # Made nullable for transition
    password_hash = db.Column(db.String(255), nullable=True)  # New hashed password column
    avatar = db.Column(db.String(150), default="default_avatar.png")
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)
        self.password = None  # Clear old plain text password
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash."""
        # If we have a hashed password, use it
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        # Otherwise, check against old plain text password (for backward compatibility)
        elif self.password:
            # If login successful with old password, migrate to hashed password
            if self.password == password:
                self.set_password(password)
                db.session.commit()
                return True
            return False
        return False

print("DEBUG: User model defined (8).")

@login_manager.user_loader
def load_user(user_id):
    print(f"DEBUG: load_user called for user_id: {user_id}")
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None

# --- Global Request Debugging ---
@app.before_request
def debug_request_info():
    print(f"\n--- Request received for: {request.path} ---")
    print(f"DEBUG: current_user.is_authenticated = {current_user.is_authenticated}")
    print(f"DEBUG: session.permanent = {session.permanent}")
    if '_user_id' in session:
        print(f"DEBUG: session['_user_id'] = {session['_user_id']}")
    else:
        print(f"DEBUG: session does not contain '_user_id'")
    print("-------------------------------------------\n")

# --- Routes ---

@app.route("/")
@login_required
def home():
    return render_template("dashboard.html", username=current_user.username)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        # Check if file was submitted
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # Check if file has a name
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        # Validate file type and save
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Prevent duplicate filenames by adding user ID prefix
            filename = f"{current_user.id}_{filename}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            
            try:
                file.save(filepath)
                flash(f"File '{file.filename}' uploaded successfully!", "success")
                socketio.emit("file_uploaded", {"filename": file.filename, "user": current_user.username})
            except Exception as e:
                flash(f"Error uploading file: {str(e)}", "danger")
        else:
            flash("Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS), "danger")
    
    return render_template("upload.html")

@app.route("/chart_data")
@login_required
def chart_data():
    # Sample data - in a real app, this would come from your database
    return jsonify({
        'labels': ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        'values': [10, 20, 30, 25, 35, 40]
    })

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Please provide both username and password", "danger")
            return render_template("login.html")
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            remember_me = bool(request.form.get('remember'))
            login_user(user, remember=remember_me)
            print(f"DEBUG: Login successful for {user.username}. 'remember' passed to login_user: {remember_me}")
            
            # Redirect to next page or home
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):  # Simple validation
                return redirect(next_page)
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "danger")
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validation
        if not username or not password:
            flash("Please provide both username and password", "danger")
            return render_template("register.html")
        
        if len(username) < 3:
            flash("Username must be at least 3 characters long", "danger")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long", "danger")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template("register.html")
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return render_template("register.html")
        
        try:
            # Create new user with hashed password
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash("Error creating account. Please try again.", "danger")
            print(f"DEBUG: Registration error: {str(e)}")
    
    return render_template("register.html")

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    username = current_user.username
    logout_user()
    session.clear()
    
    response = make_response(redirect(url_for("login")))
    
    # Clear cookies explicitly
    remember_cookie_name = app.config.get('REMEMBER_COOKIE_NAME', 'remember_token')
    session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
    
    response.set_cookie(remember_cookie_name, '', expires=0, 
                       domain=app.config.get('REMEMBER_COOKIE_DOMAIN'), 
                       path=app.config.get('REMEMBER_COOKIE_PATH', '/'))
    response.set_cookie(session_cookie_name, '', expires=0,
                       domain=app.config.get('SESSION_COOKIE_DOMAIN'),
                       path=app.config.get('SESSION_COOKIE_PATH', '/'))

    print(f"DEBUG: User {username} logged out successfully.")
    flash("You have been logged out successfully.", "info")
    return response

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(error):
    flash("File too large. Maximum size is 16MB.", "danger")
    return redirect(url_for('upload'))

# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        print(f'DEBUG: User {current_user.username} connected to SocketIO')
        emit('status', {'msg': f'{current_user.username} has connected'})

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        print(f'DEBUG: User {current_user.username} disconnected from SocketIO')

print("DEBUG: Routes and functions defined (9).")

# --- Database Migration Helper ---
def migrate_database():
    """Add password_hash column if it doesn't exist."""
    try:
        with app.app_context():
            # Check if password_hash column exists
            result = db.engine.execute("PRAGMA table_info(user)")
            columns = [row[1] for row in result]
            
            if 'password_hash' not in columns:
                print("DEBUG: Adding password_hash column to existing database...")
                db.engine.execute("ALTER TABLE user ADD COLUMN password_hash VARCHAR(255)")
                print("DEBUG: password_hash column added successfully!")
                
    except Exception as e:
        print(f"DEBUG: Migration check failed: {e}")

# --- Main execution block ---
if __name__ == "__main__":
    print("DEBUG: Entering main execution block (10).")
    with app.app_context():
        print("DEBUG: Inside app context for db.create_all() (11).")
        
        # First, add missing columns to existing database
        migrate_database()
        
        # Then create any missing tables
        db.create_all()
        print("DEBUG: Database tables checked/created (12).")
        
        # Create upload folder if it doesn't exist
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])
            print(f"DEBUG: Upload folder '{app.config['UPLOAD_FOLDER']}' created (13).")
        else:
            print(f"DEBUG: Upload folder '{app.config['UPLOAD_FOLDER']}' already exists (13).")
    
    print("DEBUG: Exited app context (14).")
    
    # Run the application
    socketio.run(app, 
                debug=True, 
                allow_unsafe_werkzeug=True,
                host='127.0.0.1',
                port=5000)
    print("DEBUG: Flask-SocketIO server started (15).")