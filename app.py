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
import requests
from sqlalchemy import inspect
import json

# NEW: Imports for OCR functionality
import cv2
from PIL import Image
import easyocr
import re
import numpy as np
import isbnlib
import io # For handling image bytes in memory

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

# --- GOOGLE_BOOKS_API_KEY Management ---
GOOGLE_BOOKS_API_KEY_FILE = 'google_books_api_key.txt'
if os.path.exists(GOOGLE_BOOKS_API_KEY_FILE):
    with open(GOOGLE_BOOKS_API_KEY_FILE, 'r') as f:
        APP_GOOGLE_BOOKS_API_KEY = f.read().strip()
    print(f"DEBUG: GOOGLE_BOOKS_API_KEY loaded from {GOOGLE_BOOKS_API_KEY_FILE}.")
else:
    APP_GOOGLE_BOOKS_API_KEY = "" # Default to empty string if file not found
    print(f"DEBUG: '{GOOGLE_BOOKS_API_KEY_FILE}' not found. Using empty API key. Consider creating this file for higher API quotas.")

# --- App Config ---
app = Flask(__name__)
app.config.update(
    SECRET_KEY=APP_SECRET_KEY,
    SQLALCHEMY_DATABASE_URI="sqlite:///site.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False, # Recommended to disable for less overhead
    UPLOAD_FOLDER="uploads/",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024, # 16MB max file size for uploads

    # Session cookie settings for security and behavior
    SESSION_COOKIE_PERMANENT=False,          # Session expires when browser closes
    SESSION_REFRESH_EACH_REQUEST=True,       # Keep session active on each request
    SESSION_COOKIE_HTTPONLY=True,            # Prevent client-side JavaScript access to cookie
    SESSION_COOKIE_SECURE=False,             # Set to True in production (requires HTTPS)
    SESSION_COOKIE_SAMESITE='Lax',           # CSRF protection (Strict, Lax, None)
    SESSION_COOKIE_DOMAIN='127.0.0.1',       # Explicitly set domain for session cookie
    SESSION_COOKIE_PATH='/',                 # Cookie valid for all paths

    # Flask-Login's "Remember Me" cookie settings
    REMEMBER_COOKIE_DURATION=timedelta(days=30), # How long "remember me" lasts
    REMEMBER_COOKIE_NAME='remember_token',       # Name of the remember me cookie
    REMEMBER_COOKIE_HTTPONLY=True,               # Prevent client-side JavaScript access
    REMEMBER_COOKIE_SECURE=False,                # Set to True in production (requires HTTPS)
    REMEMBER_COOKIE_DOMAIN='127.0.0.1',          # Keeping explicit for remember_token
    REMEMBER_COOKIE_PATH='/',                    # Cookie valid for all paths

    GOOGLE_BOOKS_API_KEY=APP_GOOGLE_BOOKS_API_KEY,
)

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx', 'docx'}
# NEW: Allowed image extensions for OCR
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}

def allowed_file(filename):
    """Checks if a file's extension is allowed for general upload."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_image_file(filename):
    """Checks if a file's extension is allowed for image OCR upload."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

print("DEBUG: App configuration loaded (3).")

db = SQLAlchemy(app)
print("DEBUG: SQLAlchemy initialized (5).")

# SocketIO initialization with CORS for broader compatibility
socketio = SocketIO(app, cors_allowed_origins="*")
print("DEBUG: SocketIO initialized (6).")

login_manager = LoginManager(app)
login_manager.login_view = "login" # The view name for the login page
login_manager.login_message = "Please log in to access this page." # Message for unauthenticated users
login_manager.login_message_category = "info" # Category for flash message styling
print("DEBUG: LoginManager initialized (7).")

# NEW: Initialize EasyOCR reader globally
try:
    # EasyOCR can be slow to initialize, do it once globally
    easy_ocr_reader = easyocr.Reader(['en'])
    print("DEBUG: EasyOCR reader initialized successfully.")
except Exception as e:
    print(f"ERROR: EasyOCR initialization failed. Make sure it's installed correctly "
          f"and language data is available: {e}")
    easy_ocr_reader = None

# --- User Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # The 'password' column is now deprecated and is kept for migration purposes
    password = db.Column(db.String(150), nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    avatar = db.Column(db.String(150), default="default_avatar.png")

    # Relationship to Book model
    books = db.relationship('Book', backref='owner', lazy=True)

    def set_password(self, password):
        """Hashes the given password and stores it."""
        self.password_hash = generate_password_hash(password)
        self.password = None  # Clear old plain text password if it exists

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        elif self.password: # Fallback for old plain text passwords during migration
            if self.password == password:
                self.set_password(password) # Migrate to hashed password on successful login
                db.session.commit()
                return True
            return False
        return False

print("DEBUG: User model defined (8).")

# --- Book Model ---
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=True)
    isbn = db.Column(db.String(20), nullable=True) # NEW: ISBN for unique identification
    cover_image_url = db.Column(db.String(500), nullable=True) # NEW: URL for book cover
    # Foreign Key to link book to a user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

print("DEBUG: Book model defined.")


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader callback."""
    print(f"DEBUG: load_user called for user_id: {user_id}")
    remember_cookie_name = app.config.get('REMEMBER_COOKIE_NAME', 'remember_token')
    if remember_cookie_name in request.cookies:
        print(f"DEBUG: '{remember_cookie_name}' cookie IS PRESENT in request.cookies.")
    else:
        print(f"DEBUG: '{remember_cookie_name}' cookie IS NOT PRESENT in request.cookies.")
    try:
        # Use db.session.get for SQLAlchemy 2.0 compatibility
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None

# --- Global Request Debugging ---
@app.before_request
def debug_request_info():
    """Logs authentication and session permanence status before each request."""
    print(f"\n--- Request received for: {request.path} ---")
    print(f"DEBUG: current_user.is_authenticated = {current_user.is_authenticated}")
    print(f"DEBUG: session.permanent = {session.permanent}")
    if '_user_id' in session: # Flask-Login stores user ID as '_user_id' in session
        print(f"DEBUG: session['_user_id'] = {session['_user_id']}")
    else:
        print(f"DEBUG: session does not contain '_user_id'")

    # ADDED: Check for presence of the main Flask session cookie
    session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
    if session_cookie_name in request.cookies:
        print(f"DEBUG: '{session_cookie_name}' cookie IS PRESENT in request.cookies.")
    else:
        print(f"DEBUG: '{session_cookie_name}' cookie IS NOT PRESENT in request.cookies.")

    print("-------------------------------------------\n")

# --- OCR Functions ---
def perform_ocr_easyocr(image_input):
    if not easy_ocr_reader:
        print("EasyOCR reader not initialized. Skipping EasyOCR.")
        return None
    try:
        # EasyOCR can directly take file path, numpy array, or image bytes
        if isinstance(image_input, str):
            results = easy_ocr_reader.readtext(image_input)
        elif isinstance(image_input, (bytes, io.BytesIO)):
            image_stream = io.BytesIO(image_input)
            img = Image.open(image_stream).convert('RGB')
            img_np = np.array(img)
            results = easy_ocr_reader.readtext(img_np)
        else:
            print(f"Error: Unsupported image input type for EasyOCR: {type(image_input)}")
            return None
        extracted_text = ""
        for (bbox, text, prob) in results:
            extracted_text += text + " "
        return extracted_text.strip()
    except Exception as e:
        print(f"An error occurred during EasyOCR: {e}")
        return None

def extract_and_validate_isbns(text):
    if not text:
        return []
    isbn_pattern = re.compile(
        r'\b(?:ISBN(?:-1[03])?:?\s*)?'
        r'((?:97[89][-\s]?)?\d{1,5}[-\s]?\d{1,7}[-\s]?\d{1,6}[-\s]?[\dX]\b)',
        re.IGNORECASE
    )
    potential_isbns = []
    for match in isbn_pattern.finditer(text):
        raw_isbn_candidate = match.group(1)
        cleaned_isbn = re.sub(r'[-\s]', '', raw_isbn_candidate).upper()
        if len(cleaned_isbn) == 10 or len(cleaned_isbn) == 13:
            potential_isbns.append(cleaned_isbn)
    valid_isbns = []
    for isbn_candidate in set(potential_isbns):
        if isbnlib.is_isbn10(isbn_candidate) or isbnlib.is_isbn13(isbn_candidate):
            valid_isbns.append(isbn_candidate)
    return sorted(set(valid_isbns))

def process_book_cover_image(image_input):
    results = {
        'full_text': None,
        'isbns': [],
        'status': 'fail',
        'message': 'Initial state'
    }
    try:
        extracted_text = perform_ocr_easyocr(image_input)
        # NEW DEBUG LINE: Check if any text was extracted
        if extracted_text:
            print(f"DEBUG: EasyOCR successfully extracted text: '{extracted_text[:100]}...'")
            results['full_text'] = extracted_text
            results['isbns'] = extract_and_validate_isbns(extracted_text)
            results['status'] = 'success'
            results['message'] = 'Text and ISBNs extracted successfully.'
        else:
            results['status'] = 'success'
            results['message'] = 'No text was found in the image.'
        return results
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during image processing: {e}")
        results['message'] = f'An unexpected error occurred: {e}'
        return results

# --- Main Routes ---
@app.route("/")
def home():
    print("DEBUG: Accessing home page.")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    print("DEBUG: Accessing login page.")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"DEBUG: Login attempt for user: {username}")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            remember = request.form.get('remember') == 'true'
            login_user(user, remember=remember)
            print(f"DEBUG: Successful login for user: {username}. Remember me: {remember}")
            # Redirect to the page the user was trying to access, or to the dashboard
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            print("DEBUG: Failed login attempt.")
    return render_template('login.html')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    print("DEBUG: Accessing signup page.")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"DEBUG: Signup attempt for user: {username}")
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        print(f"DEBUG: New user '{username}' created successfully.")
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"DEBUG: Accessing dashboard for user: {current_user.username}")
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    print(f"DEBUG: Logging out user: {current_user.username}")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route("/search_books")
@login_required
def search_books():
    """
    Searches for books using the Google Books API and returns a JSON response.
    """
    print(f"DEBUG: Entering search_books route for user: {current_user.username}")
    query = request.args.get('query')
    if not query:
        print("DEBUG: Search query is empty.")
        return jsonify([])

    print(f"DEBUG: Searching for books with query: '{query}'")

    api_url = f"https://www.googleapis.com/books/v1/volumes?q={query}&key={app.config['GOOGLE_BOOKS_API_KEY']}&maxResults=20"

    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        
        books = []
        if 'items' in data:
            for item in data['items']:
                volume_info = item.get('volumeInfo', {})
                # Skip books with no title or author
                if not volume_info.get('title') or not volume_info.get('authors'):
                    continue

                books.append({
                    'title': volume_info.get('title'),
                    'author': ', '.join(volume_info.get('authors', [])),
                    'isbn': volume_info.get('industryIdentifiers', [{}])[0].get('identifier'),
                    'cover_image_url': volume_info.get('imageLinks', {}).get('thumbnail', ''),
                    'description': volume_info.get('description', 'No description available.')
                })
        print(f"DEBUG: Found {len(books)} books for query: '{query}'.")
        return jsonify(books)

    except requests.exceptions.RequestException as e:
        print(f"ERROR: An error occurred while fetching data from the Google Books API: {e}")
        return jsonify({"error": "Failed to connect to book search service."}), 500

    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500


@app.route('/ocr_upload', methods=['POST'])
@login_required
def ocr_upload():
    print(f"DEBUG: OCR upload route accessed for user: {current_user.username}")
    if 'image' not in request.files:
        flash('No file part', 'danger')
        return jsonify({"error": "No image file part."}), 400
    
    file = request.files['image']
    if file.filename == '':
        flash('No selected file', 'danger')
        return jsonify({"error": "No selected image file."}), 400

    if file and allowed_image_file(file.filename):
        # Read the image data into memory
        image_data = file.read()
        print(f"DEBUG: Received image file for OCR. Size: {len(image_data)} bytes.")
        results = process_book_cover_image(image_data)
        
        if results['status'] == 'success':
            print(f"DEBUG: OCR processed image successfully.")
            return jsonify({
                'full_text': results['full_text'],
                'isbns': results['isbns'],
                'message': results['message']
            })
        else:
            print(f"ERROR: OCR failed with message: {results['message']}")
            return jsonify({"error": results['message']}), 500
    
    return jsonify({"error": "Invalid file type. Only image files are allowed."}), 400

@app.route('/add_book_to_library', methods=['POST'])
@login_required
def add_book_to_library():
    print(f"DEBUG: Adding book to library for user: {current_user.username}")
    try:
        data = request.json
        title = data.get('title')
        author = data.get('author')
        isbn = data.get('isbn')
        cover_image_url = data.get('cover_image_url')

        if not title:
            return jsonify({'success': False, 'message': 'Title is required.'}), 400

        # Check if the book already exists in the user's library
        existing_book = Book.query.filter_by(user_id=current_user.id, isbn=isbn).first()
        if existing_book:
            return jsonify({'success': False, 'message': 'This book is already in your library.'}), 409
        
        new_book = Book(
            title=title,
            author=author,
            isbn=isbn,
            cover_image_url=cover_image_url,
            owner=current_user
        )
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Book added to library successfully!'})
    except Exception as e:
        print(f"Error adding book to library: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Failed to add book: {str(e)}'}), 500

@app.route("/my_library")
@login_required
def my_library():
    user_books = Book.query.filter_by(user_id=current_user.id).all()
    return render_template('my_library.html', books=user_books)

# --- Database Migration Check ---
def migrate_database():
    """Checks for missing columns and adds them if necessary."""
    print("DEBUG: Checking for database migrations...")
    inspector = inspect(db.engine)
    if 'book' in inspector.get_table_names():
        book_columns = [col['name'] for col in inspector.get_columns('book')]
        
        try:
            if 'isbn' not in book_columns:
                print("DEBUG: Adding 'isbn' column to 'book' table...")
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE book ADD COLUMN isbn VARCHAR(20)"))
                    print("DEBUG: 'isbn' column added successfully!")
            
            if 'cover_image_url' not in book_columns:
                print("DEBUG: Adding 'cover_image_url' column to 'book' table...")
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE book ADD COLUMN cover_image_url VARCHAR(500)"))
                    print("DEBUG: 'cover_image_url' column added successfully!")
        
        except Exception as e:
            print(f"DEBUG: Migration check failed: {e}")

# --- Main execution block ---\r\n
if __name__ == "__main__":
    print("DEBUG: Entering main execution block (10).")
    with app.app_context():
        print("DEBUG: Inside app context for db.create_all() (11).")
        
        # It's better to run migration before create_all, in case a table already exists
        migrate_database()
        
        db.create_all()
        print("DEBUG: Database tables checked/created (12).")
        
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])
            print(f"DEBUG: Upload folder '{app.config['UPLOAD_FOLDER']}' created (13).")
        else:
            print(f"DEBUG: Upload folder '{app.config['UPLOAD_FOLDER']}' already exists (13).")
    
    print("DEBUG: Exited app context (14).")
    
    socketio.run(app, 
                 debug=True, 
                 allow_unsafe_werkzeug=True) # allow_unsafe_werkzeug required for Werkzeug 2.1+ to run in debug mode
