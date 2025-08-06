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

# NEW: Imports for OCR functionality
import cv2
from PIL import Image
import pytesseract
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
    SESSION_COOKIE_PERMANENT=False,         # Session expires when browser closes
    SESSION_REFRESH_EACH_REQUEST=True,      # Keep session active on each request
    SESSION_COOKIE_HTTPONLY=True,           # Prevent client-side JavaScript access to cookie
    SESSION_COOKIE_SECURE=False,            # Set to True in production (requires HTTPS)
    SESSION_COOKIE_SAMESITE='Lax',          # CSRF protection (Strict, Lax, None)
    SESSION_COOKIE_DOMAIN='127.0.0.1',      # Explicitly set domain for session cookie
    SESSION_COOKIE_PATH='/',                # Cookie valid for all paths

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

# --- OCR Functions (Copied from your provided script) ---

def preprocess_image_for_ocr(image_input):
    img_cv = None
    if isinstance(image_input, str):
        if not os.path.exists(image_input):
            print(f"Error: Image file not found at {image_input}")
            return None
        img_cv = cv2.imread(image_input)
        if img_cv is None:
            print(f"Error: Could not read image from path {image_input}")
            return None
    elif isinstance(image_input, Image.Image):
        img_cv = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, np.ndarray):
        img_cv = image_input
    else:
        print(f"Error: Unsupported image input type: {type(image_input)}")
        return None

    try:
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        thresh = cv2.adaptiveThreshold(blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                         cv2.THRESH_BINARY_INV, 11, 2)
        return Image.fromarray(thresh)
    except Exception as e:
        print(f"An error occurred during image preprocessing: {e}")
        return None

def perform_ocr_pytesseract(image_pil):
    if not image_pil:
        return None
    try:
        text = pytesseract.image_to_string(image_pil)
        return text
    except pytesseract.TesseractNotFoundError:
        print("Pytesseract Error: Tesseract OCR engine not found.")
        return None
    except Exception as e:
        print(f"An error occurred during pytesseract OCR: {e}")
        return None

def perform_ocr_easyocr(image_input):
    if not easy_ocr_reader:
        print("EasyOCR reader not initialized. Skipping EasyOCR.")
        return None
    try:
        # EasyOCR can directly take file path, numpy array, or image bytes
        if isinstance(image_input, str):
            results = easy_ocr_reader.readtext(image_input)
        elif isinstance(image_input, Image.Image):
            img_np = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
            results = easy_ocr_reader.readtext(img_np)
        elif isinstance(image_input, np.ndarray):
            results = easy_ocr_reader.readtext(image_input)
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

def process_book_cover_image(image_input, ocr_engine='easyocr'): # Default to easyocr for web
    results = {
        'full_text': None,
        'isbns': [],
        'status': 'fail',
        'message': 'Initial state'
    }
    
    img_for_easyocr_input = None
    img_for_pytesseract_pil = None

    try:
        if isinstance(image_input, bytes):
            # For bytes, decode to numpy array first
            nparr = np.frombuffer(image_input, np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img_cv is None:
                results['message'] = "Could not decode image bytes."
                return results
            img_for_easyocr_input = img_cv # EasyOCR can take numpy array
            img_for_pytesseract_pil = preprocess_image_for_ocr(img_cv)
            if not img_for_pytesseract_pil:
                results['message'] = "Preprocessing image from bytes failed."
                return results
        elif isinstance(image_input, str): # Path
            img_for_easyocr_input = image_input
            img_for_pytesseract_pil = preprocess_image_for_ocr(image_input)
            if not img_for_pytesseract_pil:
                results['message'] = "Preprocessing image from path failed."
                return results
        elif isinstance(image_input, Image.Image): # PIL Image
            img_for_easyocr_input = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
            img_for_pytesseract_pil = preprocess_image_for_ocr(image_input)
            if not img_for_pytesseract_pil:
                results['message'] = "Preprocessing image from PIL Image failed."
                return results
        elif isinstance(image_input, np.ndarray): # Numpy array
            img_for_easyocr_input = image_input
            img_for_pytesseract_pil = preprocess_image_for_ocr(image_input)
            if not img_for_pytesseract_pil:
                results['message'] = "Preprocessing image from numpy array failed."
                return results
        else:
            results['message'] = f"Unsupported input type for image_input: {type(image_input)}"
            return results

        extracted_text = None
        if ocr_engine == 'pytesseract':
            print("Running OCR with Pytesseract...")
            extracted_text = perform_ocr_pytesseract(img_for_pytesseract_pil)
        elif ocr_engine == 'easyocr':
            print("Running OCR with EasyOCR...")
            extracted_text = perform_ocr_easyocr(img_for_easyocr_input) # Use appropriate input for EasyOCR
        else:
            results['message'] = f"Invalid OCR engine specified: {ocr_engine}. Choose 'pytesseract' or 'easyocr'."
            return results

        if extracted_text:
            results['full_text'] = extracted_text
            results['isbns'] = extract_and_validate_isbns(extracted_text)
            results['status'] = 'success'
            results['message'] = 'Text and ISBNs extracted successfully.'
        else:
            results['message'] = f"No text extracted using {ocr_engine}."
    except Exception as e:
        results['message'] = f"An unexpected error occurred during processing: {e}"
    return results

# --- End OCR Functions ---


# --- Routes ---

@app.route("/")
@login_required
def home():
    """Renders the user's dashboard."""
    last_book = Book.query.filter_by(user_id=current_user.id).order_by(Book.id.desc()).first()
    return render_template("dashboard.html", username=current_user.username, last_book=last_book)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Handles file uploads."""
    if request.method == "POST":
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
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
    
    return render_template("upload.html", username=current_user.username)

# NEW: Route for OCR image upload and processing
@app.route("/ocr_upload", methods=["POST"])
@login_required
def ocr_upload():
    if 'image' not in request.files:
        return jsonify({"status": "error", "message": "No image file provided."}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected image file."}), 400
    
    if file and allowed_image_file(file.filename):
        try:
            # Read image into bytes in memory
            image_bytes = file.read()
            
            # Process the image using OCR functions
            # Defaulting to easyocr for web app for potentially better out-of-the-box results
            ocr_results = process_book_cover_image(image_bytes, ocr_engine='easyocr')
            
            if ocr_results['status'] == 'success':
                # Prioritize ISBN if found, otherwise use full text
                extracted_query = ""
                if ocr_results['isbns']:
                    extracted_query = ocr_results['isbns'][0] # Take the first ISBN
                elif ocr_results['full_text']:
                    # Take a reasonable portion of text if no ISBN, to avoid overly long queries
                    extracted_query = ocr_results['full_text'][:200] # Limit to first 200 chars
                
                return jsonify({
                    "status": "success",
                    "query": extracted_query,
                    "full_text": ocr_results['full_text'],
                    "isbns": ocr_results['isbns']
                })
            else:
                return jsonify({"status": "error", "message": ocr_results['message']}), 500
        except Exception as e:
            print(f"ERROR: Exception during OCR upload: {e}")
            return jsonify({"status": "error", "message": f"An unexpected error occurred during OCR: {str(e)}"}), 500
    else:
        return jsonify({"status": "error", "message": "Invalid image file type. Allowed: png, jpg, jpeg, gif, bmp, tiff."}), 400


@app.route("/chart_data")
@login_required
def chart_data():
    """Provides sample data for charts."""
    return jsonify({
        'labels': ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        'values': [10, 20, 30, 25, 35, 40]
    })

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
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
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "danger")
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
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
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return render_template("register.html")
        
        try:
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
def logout():
    """Handles user logout and clears session/cookies."""
    username = current_user.username if current_user.is_authenticated else "Guest" 
    
    logout_user() 
    session.clear() 

    response = make_response(redirect(url_for("login")))
    
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

# --- Library Routes ---
@app.route("/library", methods=["GET"])
@login_required
def library():
    """Displays the user's personal book library."""
    user_books = Book.query.filter_by(user_id=current_user.id).order_by(Book.id.desc()).all()
    return render_template("library.html", username=current_user.username, books=user_books)

@app.route("/add_book", methods=["POST"])
@login_required
def add_book():
    """Handles adding a new book to the user's library."""
    title = request.form.get("title", "").strip()
    author = request.form.get("author", "").strip()
    isbn = request.form.get("isbn", "").strip()
    cover_image_url = request.form.get("cover_image_url", "").strip()

    if not title:
        flash("Book title is required.", "danger")
        return redirect(url_for('library'))
    
    if isbn and Book.query.filter_by(isbn=isbn, user_id=current_user.id).first():
        flash(f"Book with ISBN '{isbn}' is already in your library.", "warning")
        return redirect(url_for('library'))

    new_book = Book(title=title, author=author, isbn=isbn, cover_image_url=cover_image_url, user_id=current_user.id)
    db.session.add(new_book)
    try:
        db.session.commit()
        flash(f"Book '{title}' added to your library!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding book: {str(e)}", "danger")
    
    return redirect(url_for('library'))

@app.route("/delete_book/<int:book_id>", methods=["POST"])
@login_required
def delete_book(book_id):
    """Handles deleting a book from the user's library."""
    book_to_delete = Book.query.filter_by(id=book_id, user_id=current_user.id).first()

    if book_to_delete:
        db.session.delete(book_to_delete)
        try:
            db.session.commit()
            flash(f"Book '{book_to_delete.title}' deleted from your library.", "info")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting book: {str(e)}", "danger")
    else:
        flash("Book not found or you don't have permission to delete it.", "danger")
    
    return redirect(url_for('library'))

@app.route("/search_books", methods=["GET"])
@login_required
def search_books():
    """Searches for books using the Google Books API."""
    query = request.args.get("query", "").strip()
    if not query:
        return jsonify([])
    
    google_books_api_url = "https://www.googleapis.com/books/v1/volumes"
    params = {
        "q": query,
        "maxResults": 10,
        "key": app.config["GOOGLE_BOOKS_API_KEY"]
    }

    try:
        response = requests.get(google_books_api_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        books_found = []
        for item in data.get("items", []):
            volume_info = item.get("volumeInfo", {})
            
            title = volume_info.get("title", "No Title Available")
            authors = volume_info.get("authors", ["Unknown Author"])
            author_str = ", ".join(authors)
            
            isbn = None
            for industry_id in volume_info.get("industryIdentifiers", []):
                if industry_id.get("type") == "ISBN_13":
                    isbn = industry_id.get("identifier")
                    break
                elif industry_id.get("type") == "ISBN_10":
                    isbn = industry_id.get("identifier")
            
            cover_image_url = volume_info.get("imageLinks", {}).get("thumbnail")
            
            books_found.append({
                "title": title,
                "author": author_str,
                "isbn": isbn,
                "cover_image_url": cover_image_url
            })
        return jsonify(books_found)

    except requests.exceptions.RequestException as e:
        print(f"ERROR: Google Books API request failed: {e}")
        return jsonify({"error": "Failed to fetch books from external API."}), 500
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during book search: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500


# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    """Custom 404 Not Found error handler."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Custom 500 Internal Server Error handler."""
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(error):
    """Custom 413 Payload Too Large error handler for file uploads."""
    flash("File too large. Maximum size is 16MB.", "danger")
    return redirect(url_for('upload'))

# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    """Handles new SocketIO client connections."""
    if current_user.is_authenticated:
        print(f'DEBUG: User {current_user.username} connected to Socket.IO')
        emit('status', {'msg': f'{current_user.username} has connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handles SocketIO client disconnections."""
    if current_user.is_authenticated:
        print(f'DEBUG: User {current_user.username} disconnected from Socket.IO')

print("DEBUG: Routes and functions defined (9).")

# --- Database Migration Helper ---
def migrate_database():
    """Adds password_hash, isbn, and cover_image_url columns to existing tables if they don't exist."""
    try:
        with app.app_context():
            user_columns_result = db.engine.execute("PRAGMA table_info(user)")
            user_columns = [row[1] for row in user_columns_result]
            
            if 'password_hash' not in user_columns:
                print("DEBUG: Adding password_hash column to existing User table...")
                db.engine.execute("ALTER TABLE user ADD COLUMN password_hash VARCHAR(255)")
                print("DEBUG: password_hash column added successfully!")
            
            inspector = inspect(db.engine)
            if not inspector.has_table("book"):
                print("DEBUG: 'book' table does not exist. It will be created by db.create_all().")
            else:
                book_columns_result = db.engine.execute("PRAGMA table_info(book)")
                book_columns = [row[1] for row in book_columns_result]
                
                if 'isbn' not in book_columns:
                    print("DEBUG: Adding 'isbn' column to 'book' table...")
                    db.engine.execute("ALTER TABLE book ADD COLUMN isbn VARCHAR(20)")
                    print("DEBUG: 'isbn' column added successfully!")
                
                if 'cover_image_url' not in book_columns:
                    print("DEBUG: Adding 'cover_image_url' column to 'book' table...")
                    db.engine.execute("ALTER TABLE book ADD COLUMN cover_image_url VARCHAR(500)")
                    print("DEBUG: 'cover_image_url' column added successfully!")
                
    except Exception as e:
        print(f"DEBUG: Migration check failed: {e}")

# --- Main execution block ---
if __name__ == "__main__":
    print("DEBUG: Entering main execution block (10).")
    with app.app_context():
        print("DEBUG: Inside app context for db.create_all() (11).")
        
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
                allow_unsafe_werkzeug=True, 
                host='127.0.0.1',           
                port=5000)                  
    print("DEBUG: Flask-SocketIO server started (15).")
