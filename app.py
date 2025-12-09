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

# Imports for OCR functionality
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
    print(f"DEBUG: New SECRET_KEY generated and saved to {SECRET_KEY_FILE}.")

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = APP_SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///booksnap.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

print("DEBUG: App and extensions initialized (3).")

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    books = db.relationship('Book', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    author = db.Column(db.String(250), nullable=True)
    isbn = db.Column(db.String(20), nullable=True)
    cover_image_url = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- OCR Utility Functions ---
# Initialize the EasyOCR reader
reader = easyocr.Reader(['en'])

def process_image_for_ocr(image_bytes):
    """
    Processes an image to extract text using EasyOCR and attempts to find book details.
    
    Args:
        image_bytes: The image data as bytes.
        
    Returns:
        A tuple of (book_info_list, ocr_text). book_info_list is a list of dictionaries or an empty list,
        and ocr_text is the full text extracted from the image.
    """
    try:
        # Decode the image bytes into a format readable by OpenCV
        image_np = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(image_np, cv2.IMREAD_COLOR)

        if img is None:
            print("ERROR: OpenCV could not decode image.")
            return [], ""

        # Perform OCR on the image
        results = reader.readtext(img, detail=0)
        
        # Join the list of detected texts into a single string
        full_text = " ".join(results)
        print(f"DEBUG: Full OCR Text: {full_text}")

        book_info_list = []

        # Use the full extracted text as the search query for the Google Books API
        if full_text:
            query = full_text
            print(f"DEBUG: Searching Google Books with query based on full OCR text: {query}")
            response = requests.get(f"https://www.googleapis.com/books/v1/volumes?q={query}")
            data = response.json()
            
            if 'items' in data and len(data['items']) > 0:
                for item in data['items']:
                    book_data = item['volumeInfo']
                    book_info = {
                        'title': book_data.get('title', 'Unknown Title'),
                        'author': ', '.join(book_data.get('authors', [])) or 'Unknown Author',
                        'isbn': book_data.get('industryIdentifiers', [{}])[0].get('identifier', None),
                        'cover_image_url': book_data.get('imageLinks', {}).get('thumbnail', '')
                    }
                    book_info_list.append(book_info)
                print(f"DEBUG: Found {len(book_info_list)} books from the OCR text.")
            else:
                print("DEBUG: Google Books API returned no results for the OCR text.")

        return book_info_list, full_text

    except Exception as e:
        print(f"ERROR: An error occurred during OCR processing: {e}")
        return [], ""


# --- Routes ---
@app.route('/')
@login_required
def home():
    # Placeholder for dashboard data
    last_book = Book.query.filter_by(user_id=current_user.id).order_by(Book.id.desc()).first()
    return render_template('dashboard.html', username=current_user.username, last_book=last_book)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html')
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/ocr_upload', methods=['GET'])
@login_required
def ocr_upload():
    return render_template('ocr_upload.html', username=current_user.username)
    
@app.route('/process_ocr_image', methods=['POST'])
@login_required
def process_ocr_image():
    if 'file' not in request.files:
        print("ERROR: No file part in the request.")
        return jsonify({'success': False, 'message': 'No file uploaded.'})

    file = request.files['file']
    if file.filename == '':
        print("ERROR: No selected file.")
        return jsonify({'success': False, 'message': 'No selected file.'})

    if file:
        file_bytes = file.read()
        book_info_list, ocr_text = process_image_for_ocr(file_bytes)
        
        if book_info_list:
            return jsonify({'success': True, 'book_info': book_info_list, 'ocr_text': ocr_text})
        else:
            return jsonify({'success': False, 'message': 'No books found or details could not be retrieved. Please try a manual search.', 'ocr_text': ocr_text})

@app.route('/ocr_results', methods=['GET'])
@login_required
def ocr_results():
    return render_template('ocr_results.html', username=current_user.username)

@app.route('/search_manual', methods=['POST'])
@login_required
def search_manual():
    try:
        data = request.json
        title = data.get('title')
        author = data.get('author')

        if not title:
            return jsonify({'success': False, 'message': 'Title is required for a manual search.'}), 400

        query = f"intitle:{title}"
        if author:
            query += f"+inauthor:{author}"
        
        response = requests.get(f"https://www.googleapis.com/books/v1/volumes?q={query}")
        data = response.json()
        
        book_info_list = []
        if 'items' in data:
            for item in data['items']:
                book_data = item['volumeInfo']
                book_info = {
                    'title': book_data.get('title', 'Unknown Title'),
                    'author': ', '.join(book_data.get('authors', [])) or 'Unknown Author',
                    'isbn': book_data.get('industryIdentifiers', [{}])[0].get('identifier', None),
                    'cover_image_url': book_data.get('imageLinks', {}).get('thumbnail', '')
                }
                book_info_list.append(book_info)
        
        if book_info_list:
            return jsonify({'success': True, 'book_info': book_info_list})
        else:
            return jsonify({'success': False, 'message': 'No books found with that title and author.'})

    except Exception as e:
        print(f"ERROR: An error occurred during manual search: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred during the search.'}), 500


@app.route('/my_library')
@login_required
def my_library():
    books = Book.query.filter_by(user_id=current_user.id).order_by(Book.title).all()
    return render_template('my_library.html', username=current_user.username, books=books)

@app.route('/add_book_to_library', methods=['POST'])
@login_required
def add_book_to_library():
    try:
        data = request.json
        title = data.get('title')
        author = data.get('author')
        isbn = data.get('isbn')
        cover_image_url = data.get('cover_image_url')

        if not title:
            return jsonify({'success': False, 'message': 'Book title is required.'}), 400

        new_book = Book(
            title=title,
            author=author,
            isbn=isbn,
            cover_image_url=cover_image_url,
            user_id=current_user.id
        )
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Book added successfully!'})

    except Exception as e:
        print(f"ERROR: An error occurred while adding book: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred.'}), 500

@app.route('/delete_book/<int:book_id>', methods=['POST'])
@login_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.user_id != current_user.id:
        flash('You are not authorized to delete this book.', 'danger')
        return redirect(url_for('my_library'))

    try:
        db.session.delete(book)
        db.session.commit()
        flash('Book deleted successfully.', 'success')
        return redirect(url_for('my_library'))
    except Exception as e:
        db.session.rollback()
        print(f"ERROR: An error occurred while deleting the book: {e}")
        flash('An error occurred. Could not delete book.', 'danger')
        return redirect(url_for('my_library'))


def migrate_database():
    """Checks and adds necessary columns to the database."""
    with app.app_context():
        inspector = inspect(db.engine)
        if 'book' not in inspector.get_table_names():
            print("DEBUG: 'book' table does not exist. Skipping migration check.")
            return

        book_columns = [col['name'] for col in inspector.get_columns('book')]
        
        try:
            # Check and add cover_image_url column
            if 'cover_image_url' not in book_columns:
                print("DEBUG: Adding 'cover_image_url' column to 'book' table...")
                with db.engine.connect() as connection:
                    connection.execute(db.text("ALTER TABLE book ADD COLUMN cover_image_url VARCHAR(500)"))
                    print("DEBUG: 'cover_image_url' column added successfully!")
        
        except Exception as e:
            print(f"DEBUG: Migration check failed: {e}")

# --- Main execution block ---

if __name__ == "__main__":
    print("DEBUG: Entering main execution block (10).")
    with app.app_context():
        print("DEBUG: Inside app context for db.create_all() (11).")
        
        #Running migration before create_all, in case a table already exists [Changes]
        migrate_database()
        
        db.create_all()
        print("DEBUG: Database tables checked/created (12).")
        
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])
            print(f"DEBUG: Upload folder '{app.config['UPLOAD_FOLDER']}' created (13).")
        else:
            print(f"DEBUG: Upload folder '{app.config['UPLOAD_FOLDER']}' already exists (13).")
        
    socketio.run(app, debug=True, port=5000)