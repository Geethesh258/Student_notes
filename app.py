from flask import Flask,abort ,redirect, url_for, render_template, request
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from pymongo import MongoClient
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import base64
from flask_session import Session  
from PIL import Image
from markupsafe import Markup
import io
from werkzeug.utils import secure_filename
from io import BytesIO
from werkzeug.exceptions import RequestEntityTooLarge
from flask import flash
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from flask import send_file
from flask import send_from_directory
import time
import uuid
from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
import threading
from datetime import datetime, timedelta
from flask import current_app
 
from itsdangerous import URLSafeTimedSerializer
import json
from bson.binary import Binary
from itsdangerous import URLSafeTimedSerializer

from dotenv import load_dotenv
import mimetypes
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") # Replace with a secure key in production# Allow uploads up to 1 GB
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 
app.config['SESSION_TYPE'] = 'filesystem'  # store sessions in files
app.config['SESSION_PERMANENT'] = False
Session(app)
serializer = URLSafeTimedSerializer(app.secret_key)
@app.template_filter('b64encode')
def b64encode_filter(data):
    if isinstance(data, (bytes, bytearray)):
        encoded = base64.b64encode(data).decode('utf-8')
        return Markup(encoded)
    return data  # If not bytes, just return as is

app.config["MONGO_URI"] = os.getenv("MONGO_URI")
MONGO_URI = os.getenv("MONGO_URI")
mongo = PyMongo(app, uri=MONGO_URI)

# Configuration

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
# Flask-Mail config
# Flask-Mail configuration from .env
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True") == "True"
app.config["MAIL_USE_SSL"] = False  # keep TLS enabled, SSL off
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash("File is too large. Max size is 100MB.")  # Update size if needed
    return redirect(request.url)


@app.route('/debug_dbs')
def debug_dbs():
    client = MongoClient(os.getenv("MONGO_URI"))
    print("Databases:", client.list_database_names())
    return {"databases": client.list_database_names()}


# ----------------- MongoDB Setup -------------------

client = MongoClient(os.getenv("MONGO_URI"))
db = client["student_notes"]
users = db["users"]
notes_collection = db["notes"]
assignments_collection = db["assignments"]
captured_data=db["captured_image"]
profile_pic=db["profile_pic"]
activities=db["activities"]
feedback_collection = db["feedback"] 
# Helper: check allowed file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------- Flask-Login Setup -------------------
app.secret_key = os.getenv("SECRET_KEY")
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "info"
login_manager.init_app(app)
# ----------------- Google OAuth Setup -------------------
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")


# Make sure folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs("uploads/assignments", exist_ok=True)

#google oauth
# Google OAuth blueprint
import os
from flask_dance.contrib.google import make_google_blueprint

# Load from environment
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")

google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_url="/google_login"
)

# Only register the blueprint if not already registered
if "google" not in app.blueprints:
    app.register_blueprint(google_bp, url_prefix="/login")
else:
    print("⚠️ Google blueprint already registered, skipping registration.")

#usermixin
class User(UserMixin):
    def __init__(self, id, email, username, profile_pic=None, activities=None):
        self.id = str(id)
        self.email = email
        self.username = username
        self.profile_pic = profile_pic
        self.activities = activities or []
    # Optional: Add methods to add activities etc.

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(user_id):
    try:
        # Convert user_id string back to ObjectId for Mongo query
        user_data = users.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None

    if not user_data:
        return None

    return User(
        id=str(user_data['_id']),  # ✅ MUST be string
        email=user_data.get('email'),
        username=user_data.get('name'),
        profile_pic=user_data.get('profile_pic'),
        activities=user_data.get('activities', [])
    )

    

# ---------------- Email Sending Function ---------------- #
# send email reminder
def send_email_reminder(to_email, title, due_date):
    try:
        subject = f"📢 Assignment Reminder: {title} due on {due_date}"
        body = f"""
Hello 👋,

This is a friendly reminder that your assignment **{title}** is due on **{due_date}** ⏳.

Please make sure to submit it on time ✅.

Best regards,  
Your Student Notes App 📚
"""

        # Email config
        MAIL_SERVER = os.getenv("MAIL_SERVER")
        MAIL_PORT = int(os.getenv("MAIL_PORT"))
        MAIL_USERNAME = os.getenv("MAIL_USERNAME")
        MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

        # Create message
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = MAIL_USERNAME
        msg["To"] = to_email

        # Send email
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)

        print(f"✅📧 Email sent successfully to {to_email} for assignment '{title}' due on {due_date}")

    except Exception as e:
        print(f"❌🚫 Failed to send email to {to_email}. Error: {e}")


# check assignments due in 2 days
def check_due_assignments():
    print("\n⏰🔍 Checking for assignments due in 2 days...")

    target_date_str = (datetime.now().date() + timedelta(days=2)).isoformat()

    due_assignments = assignments_collection.find({
        "due_date": target_date_str,
        "reminder_sent": {"$ne": True}
    })

    for assignment in due_assignments:
        print(f"📢 Sending reminder to {assignment['user_email']} for '{assignment['title']}' due on {assignment['due_date']}")
        send_email_reminder(
            assignment["user_email"],
            assignment["title"],
            assignment["due_date"]
        )
        assignments_collection.update_one(
            {"_id": assignment["_id"]},
            {"$set": {"reminder_sent": True}}
        )


# run reminder in background
def start_reminder_thread():
    def run():
        while True:
            print("⏳ Waiting for next reminder check...")
            check_due_assignments()
            time.sleep(86400)  # runs once every 24 hours (use 20 for testing)
    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()

        # ----------------- Register -------------------
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash, redirect, url_for, render_template, request
from flask_login import login_user, current_user
def generate_reset_token(email):

    return serializer.dumps(email, salt='password-reset-salt')

def get_email_from_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except Exception:
        return None

# ----------------- Register Route -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if users.find_one({'email': email}):
            flash("Email already registered", "danger")
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_pw,
            "profile_pic": None,
            "activities": [],
            "captured_image": None
        })

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# ----------------- Manual Login -----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        user_data = users.find_one({'email': email})
        if user_data and user_data.get('password') and check_password_hash(user_data['password'], password):
            user = User(
                id=str(user_data['_id']),
                email=user_data.get('email'),
                username=user_data.get('name'),
                profile_pic=user_data.get('profile_pic'),
                activities=user_data.get('activities', [])
            )
            login_user(user, remember=True)  # ✅ keeps user logged in
            flash("Login successful!", "success")
            return redirect(url_for('home'))

        flash("Invalid email or password", "danger")
    return render_template('login.html')

# ----------------- Update Password -----------------
@app.route('/update_password', methods=['POST'])
def update_password():
    new_password = request.form['new_password'].strip()
    if not new_password:
        flash("Password cannot be empty", "danger")
        return redirect(url_for('home'))

    # Always hash the new password before saving
    hashed_pw = generate_password_hash(new_password)

    # Update in MongoDB
    users.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'password': hashed_pw}}
    )

    flash("Password updated successfully!", "success")
    return redirect(url_for('home'))

# ----------------- Google Login -----------------
@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for('login'))

    info = resp.json()
    email = info['email']
    name = info.get('name', email.split('@')[0])
    profile_pic = info.get('picture')

    user_data = users.find_one({'email': email})
    if not user_data:
        users.insert_one({
            "name": name,
            "email": email,
            "password": None,
            "profile_pic": profile_pic,
            "activities": [],
            "captured_image": None
        })
        user_data = users.find_one({'email': email})

    user = User(
        id=user_data['_id'],
        email=user_data['email'],
        username=user_data.get('name'),
        profile_pic=user_data.get('profile_pic'),
        activities=user_data.get('activities', [])
    )
    login_user(user)
    return redirect(url_for('home'))

# ----------------- Logout -----------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# ----------------- Home -----------------
@app.route('/home')
@login_required
def home():
    return render_template('home.html')


#profile
@app.route("/profile")
@login_required
def profile():
    user_data = users.find_one({"email": current_user.email})
    return render_template("profile.html", user=user_data)

#profile edit
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    user_data = users.find_one({"email": current_user.email})

    if request.method == "POST":
        new_name = request.form.get("name")
        
        # Handle profile pic upload
        pic = request.files.get("profile_pic")
        pic_filename = user_data.get("profile_pic")  # default keep existing

        if pic and pic.filename != "":
            pic_filename = secure_filename(pic.filename)
            pic.save(os.path.join("static/profile_pics", pic_filename))

        # Update MongoDB user doc
        users.update_one(
            {"email": current_user.email},
            {"$set": {"name": new_name, "profile_pic": pic_filename}}
        )
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    return render_template("edit_profile.html", user=user_data)

#change profile profile
@app.route("/profile/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pass = request.form.get("current_password")
        new_pass = request.form.get("new_password")
        confirm_pass = request.form.get("confirm_password")

        user_data = users.find_one({"email": current_user.email})

        if not check_password_hash(user_data["password"], current_pass):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("change_password"))

        if new_pass != confirm_pass:
            flash("New password and confirm password do not match.", "error")
            return redirect(url_for("change_password"))

        new_hash = generate_password_hash(new_pass)
        users.update_one({"email": current_user.email}, {"$set": {"password": new_hash}})

        flash("Password changed successfully!", "success")
        return redirect(url_for("profile"))

    return render_template("change_password.html")

#delete profile
@app.route("/profile/delete_account", methods=["POST"])
@login_required
def delete_account():
    users.delete_one({"email": current_user.email})
    logout_user()
    flash("Your account has been deleted.", "info")
    return redirect(url_for("register"))

# ----------------- Default Route -------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))   # already logged in → go to homepage
    else:
        return redirect(url_for('login'))  # not logged in → go to login page



#uploaded space
# --------------- Serve Uploaded Files (image/pdf) ---------------

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resize_image(path, max_size=(1024, 1024)):
    img = Image.open(path)
    img.thumbnail(max_size)
    img.save(path)

@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''



#uplaod route
@app.route('/upload_notes', methods=['GET', 'POST'])
@login_required
def upload_notes():
    if request.method == 'POST':
        subject = request.form.get('subject')
        topic = request.form.get('topic')
        due_date = datetime.now().strftime("%Y-%m-%d")  # Replace if your form has a due_date field
        uploaded_by = current_user.username
        user_email = current_user.email  # 🔹 Data isolation field

        # File Upload
        if 'file' in request.files and request.files['file'].filename != '':
            file = request.files['file']
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{int(time.time())}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)

                # Optional image resize
                if filename.lower().endswith(('png', 'jpg', 'jpeg')):
                    resize_image(file_path)

                notes_collection.insert_one({
                    "subject": subject,
                    "topic": topic,
                    "due_date": due_date,
                    "uploaded_by": uploaded_by,
                    "user_email": user_email,  # 🔹 Added
                    "filename": unique_filename,
                    "filepath": f"uploads/{unique_filename}"
                })

                flash("File uploaded successfully!", "success")
                return redirect(url_for('upload_notes'))
            else:
                flash("Unsupported file type.", "error")
                return redirect(url_for('upload_notes'))

        # Captured Image Upload (base64)
        captured_data = request.form.get('captured')
        if captured_data:
            try:
                header, encoded = captured_data.split(",", 1)
                image_data = base64.b64decode(encoded)
                filename = f"{subject}_{topic}_{int(time.time())}_capture.jpg"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                img = Image.open(BytesIO(image_data))
                img.thumbnail((800, 600))
                img.save(file_path)

                notes_collection.insert_one({
                    "subject": subject,
                    "topic": topic,
                    "due_date": due_date,
                    "uploaded_by": uploaded_by,
                    "user_email": user_email,  # 🔹 Added
                    "filename": filename,
                    "filepath": f"uploads/{filename}"
                })

                flash("Captured image uploaded successfully!", "success")
                return redirect(url_for("upload_notes"))
            except Exception as e:
                print("Capture error:", e)
                flash("Failed to upload captured image.", "error")
                return redirect(url_for("upload_notes"))

        flash("No file or image provided.", "error")
        return redirect(url_for("upload_notes"))

    return render_template("upload_notes.html")

# ---------------- Search Notes ----------------
@app.route('/search_notes', methods=['GET', 'POST'])
@login_required
def search_notes():
    results = []
    if request.method == 'POST':
        query = request.form.get('query', "").strip()
        regex_query = {'$regex': query, '$options': 'i'}

        # Only search within the logged-in user's notes
        results = list(notes_collection.find({
            '$or': [
                {'subject': regex_query},
                {'topic': regex_query}
            ],
            'user_email': current_user.email  # Data isolation
        }))

        # Show message if no results
        if not results:
            flash("No results found.", "info")

    return render_template('search_notes.html', results=results)


# ---------------- View Note ----------------
@app.route('/view_notes/<note_id>')
@login_required
def view_notes(note_id):
    note = notes_collection.find_one({'_id': ObjectId(note_id)})
    if not note:
        flash("Note not found.", "error")
        return redirect(url_for("search_notes"))
    return render_template("view_notes.html", note=note, current_time=datetime.now().timestamp())

# ---------------- Download Note ----------------
@app.route("/download_note/<note_id>")
@login_required
def download_note(note_id):
    note = notes_collection.find_one({"_id": ObjectId(note_id), "uploaded_by": current_user.username})

    if not note:
        flash("Note not found.", "error")
        return redirect(url_for("search_notes"))

    filepath = note.get("filepath")
    filename = note.get("filename")

    if filepath:
        full_path = os.path.join(app.root_path, 'static', filepath)
        if os.path.exists(full_path):
            return send_file(full_path, as_attachment=True, download_name=filename)
    
    flash("File not found on server.", "error")
    return redirect(url_for("search_notes"))

# ---------------- Edit Note ----------------
@app.route('/edit_note/<note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = notes_collection.find_one({'_id': ObjectId(note_id)})

    if not note:
        flash("Note not found.", "error")
        return redirect(url_for('search_notes'))

    if request.method == 'POST':
        subject = request.form['subject']
        topic = request.form['topic']

        update_data = {
            'subject': subject,
            'topic': topic
        }

        file = request.files.get('file')
        captured_data = request.form.get('captured_image')

        old_file = note.get('filename')
        old_captured = note.get('captured_image')

        # Handle file upload
        if file and file.filename:
            if allowed_file(file.filename):
                # Delete old captured image if any
                if old_captured:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_captured)
                    if os.path.exists(old_path):
                        os.remove(old_path)

                filename = secure_filename(file.filename)
                unique_filename = f"{int(time.time())}_{filename}"
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(save_path)

                if filename.lower().endswith(('png', 'jpg', 'jpeg')):
                    resize_image(save_path)

                update_data['filename'] = unique_filename
                update_data['filepath'] = f"uploads/{unique_filename}"
                update_data['captured_image'] = None
            else:
                flash('Invalid file type.', 'error')
                return redirect(request.url)

        # Handle captured image upload (base64)
        elif captured_data:
            if old_file:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_file)
                if os.path.exists(old_path):
                    os.remove(old_path)

            try:
                image_data = captured_data.split(',')[1]
                img = Image.open(BytesIO(base64.b64decode(image_data)))
                img_filename = secure_filename(f"{note_id}_captured.png")
                img_path = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                img.thumbnail((800, 600))
                img.save(img_path)

                update_data['captured_image'] = img_filename
                update_data['filename'] = None
                update_data['filepath'] = None
            except Exception as e:
                flash("Failed to process captured image.", "error")
                return redirect(request.url)

        notes_collection.update_one({'_id': ObjectId(note_id)}, {'$set': update_data})

        flash("Note updated successfully", "success")
        return redirect(url_for('search_notes'))

    return render_template('edit_note.html', note=note)

# ---------------- Delete Note ----------------
@app.route('/delete_note/<note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = notes_collection.find_one({'_id': ObjectId(note_id)})

    if not note:
        flash("Note not found.", "error")
        return redirect(url_for('search_notes'))

    # Delete uploaded files if they exist
    filename = note.get('filename')
    if filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)

    captured_image = note.get('captured_image')
    if captured_image:
        captured_path = os.path.join(app.config['UPLOAD_FOLDER'], captured_image)
        if os.path.exists(captured_path):
            os.remove(captured_path)

    notes_collection.delete_one({'_id': ObjectId(note_id)})

    flash("Note deleted successfully.", "success")
    return redirect(url_for('search_notes'))

# upload assignment

# Allowed fields for output (no duplicates)
ALLOWED_FIELDS = [
    '_id', 'user_email', 'subject', 'title', 'due_date', 'upload_date',
    'file', 'captured_image', 'captured_mime', 'reminder_sent', 'file_data', 'file_name'
]

# ------------------ UPLOAD ASSIGNMENT ------------------
@app.route("/upload_assignments", methods=["GET", "POST"])
@login_required
def upload_assignment():
    if request.method == "POST":
        subject = request.form.get("subject")
        title = request.form.get("title")
        due_date_str = request.form.get("due_date") or None  # keep as string

        file = request.files.get("file")
        file_name = None
        image_mime = None
        captured_image_binary = None

        # Save uploaded file to disk
        if file and file.filename != "":
            if not allowed_file(file.filename):
                flash("Invalid file type.", "error")
                return redirect(request.url)

            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            # Resize if image
            if filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
                try:
                    img = Image.open(file_path)
                    img.thumbnail((1024, 768))
                    img.save(file_path)
                except Exception:
                    flash("Error processing image.", "error")
                    return redirect(request.url)

            if os.path.getsize(file_path) > app.config['MAX_CONTENT_LENGTH']:
                os.remove(file_path)
                flash("File too large. Max size is 16 MB.", "error")
                return redirect(request.url)

            file_name = unique_filename

        # Captured image (base64)
        captured_data = request.form.get("captured")
        if captured_data:
            try:
                header, encoded = captured_data.split(",", 1)
                captured_image_binary = Binary(base64.b64decode(encoded))
                image_mime = header.split(";")[0].split(":")[1]
            except Exception:
                flash("Failed to process captured image.", "error")
                return redirect(request.url)

        # Save to MongoDB (only one method: file OR captured image)
        assignment_doc = {
            "user_email": current_user.email,
            "subject": subject,
            "title": title,
            "due_date": due_date_str,  # string format YYYY-MM-DD
            "upload_date": datetime.now(),
            "file": file_name if file_name else None,
            "captured_image": captured_image_binary,
            "captured_mime": image_mime,
            "reminder_sent": False,
            "file_data": None,  # reserved for DB file storage
            "file_name": None
        }

        assignments_collection.insert_one(assignment_doc)
        flash("Assignment uploaded successfully!", "success")
        return redirect(url_for("upload_assignment"))

    # Only show current user's assignments with projection
    user_assignments = list(assignments_collection.find(
        {"user_email": current_user.email},
        {field: 1 for field in ALLOWED_FIELDS}
    ))
    return render_template("upload_assignment.html", assignments=user_assignments)

# ------------------ SEARCH ASSIGNMENT ------------------

ALLOWED_FIELDS = [
    "_id", "user_email", "subject", "title", "due_date", "upload_date",
    "file", "captured_image", "captured_mime", "reminder_sent"
]

@app.route('/search_assignment', methods=['GET', 'POST'])
@login_required
def search_assignment():
    query = request.form.get('query', "").strip() if request.method == "POST" else ""
    results = []

    if query:
        # Search by subject or title for the logged-in user
        assignments = list(assignments_collection.find(
            {
                "$or": [
                    {"subject": {"$regex": query, "$options": "i"}},
                    {"title": {"$regex": query, "$options": "i"}}
                ],
                "user_email": current_user.email
            },
            {field: 1 for field in ALLOWED_FIELDS}
        ))

        for assignment in assignments:
            # If file is stored as a UUID filename in static/uploads
            if assignment.get('file') and isinstance(assignment['file'], str):
                assignment['file_url'] = url_for('static', filename=f"uploads/{assignment['file']}")
                # Try to guess the MIME type for preview
                mime_type, _ = mimetypes.guess_type(assignment['file'])
                assignment['file_mime'] = mime_type or 'application/octet-stream'

            # If captured image is stored as binary
            if assignment.get('captured_image') and not isinstance(assignment['captured_image'], str):
                assignment['captured_image'] = base64.b64encode(assignment['captured_image']).decode('utf-8')

        results = assignments

        if not results:
            flash("No results found.", "info")

    return render_template(
        'search_assignment.html',
        results=results,
        query=query,
        current_time=int(time.time()),
        os=os
    )

@app.route('/view_assignment/<assignment_id>')
@login_required
def view_assignment(assignment_id):

    assignment = assignments_collection.find_one(
        {"_id": ObjectId(assignment_id), "user_email": current_user.email},
        {field: 1 for field in ALLOWED_FIELDS}
    )
    
    if not assignment:
        abort(404)

    # If file is stored as binary in DB
    if assignment.get('file') and not isinstance(assignment['file'], str):
        assignment['file_data'] = base64.b64encode(assignment['file']).decode('utf-8')
        assignment['file_mime'] = assignment.get('file_mime', 'application/octet-stream')

    # If file is stored as filename (string)
    elif isinstance(assignment.get('file'), str):
        assignment['file_url'] = url_for('static', filename=f"uploads/{assignment['file']}")

    # If captured image is stored as binary in DB
    if assignment.get('captured_image') and not isinstance(assignment['captured_image'], str):
        assignment['captured_image'] = base64.b64encode(assignment['captured_image']).decode('utf-8')

    return render_template(
        'view_assignment.html',
        assignment=assignment,
        os=os
    )

# ------------------ DOWNLOAD ASSIGNMENT ------------------
@app.route("/download_assignment/<assignment_id>")
@login_required
def download_assignment(assignment_id):
    assignment = assignments_collection.find_one(
        {"_id": ObjectId(assignment_id), "user_email": current_user.email},
        {field: 1 for field in ALLOWED_FIELDS}
    )

    if not assignment:
        flash("Assignment not found.", "error")
        return redirect(url_for("search_assignment"))

    if assignment.get("file"):  # Disk file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], assignment["file"])
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=assignment["file"])

    if assignment.get("captured_image"):  # Binary stored image
        return send_file(BytesIO(assignment["captured_image"]), mimetype=assignment.get("captured_mime", "image/png"),
                         as_attachment=True, download_name="captured_image.png")

    flash("No file found.", "error")
    return redirect(url_for("search_assignment"))

# ------------------ EDIT ASSIGNMENT ------------------
@app.route('/edit_assignment/<assignment_id>', methods=['GET', 'POST'])
@login_required
def edit_assignment(assignment_id):
    assignment = assignments_collection.find_one(
        {'_id': ObjectId(assignment_id), "user_email": current_user.email},
        {field: 1 for field in ALLOWED_FIELDS}
    )

    if not assignment:
        flash("Assignment not found", "error")
        return redirect(url_for('search_assignment'))

    if request.method == 'POST':
        subject = request.form.get('subject')
        title = request.form.get('title')
        due_date_str = request.form.get('due_date') or None
        captured_image_dataurl = request.form.get('captured_image')

        update_data = {
            'subject': subject,
            'title': title,
            'due_date': due_date_str,
            'reminder_sent': False
        }

        uploaded_file = request.files.get('file')
        if uploaded_file and uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            uploaded_file.save(file_path)
            update_data['file'] = unique_filename
            update_data['captured_image'] = None
            update_data['captured_mime'] = None
        elif captured_image_dataurl:
            header, encoded = captured_image_dataurl.split(',', 1)
            update_data['captured_image'] = Binary(base64.b64decode(encoded))
            update_data['captured_mime'] = header.split(';')[0].split(':')[1]
            update_data['file'] = None
        # else keep existing

        assignments_collection.update_one({'_id': ObjectId(assignment_id)}, {'$set': update_data})
        flash('Assignment updated successfully!', 'success')
        return redirect(url_for('search_assignment'))

    return render_template('edit_assignment.html', assignment=assignment)


@app.route('/assignment_file/<assignment_id>')
@login_required
def assignment_file(assignment_id):
    assignment = assignments_collection.find_one({'_id': ObjectId(assignment_id)})
    if not assignment:
        abort(404)

    if assignment.get('file_data'):
        file_data = assignment['file_data']
        file_name = assignment.get('file_name', 'file')
        return send_file(io.BytesIO(file_data), download_name=file_name, as_attachment=False)
    elif assignment.get('captured_image'):
        image_data = assignment['captured_image']
        mime = assignment.get('captured_mime', 'image/jpeg')
        return send_file(io.BytesIO(image_data), mimetype=mime)
    else:
        abort(404)

@app.route("/delete_assignment/<assignment_id>")
@login_required
def delete_assignment(assignment_id):
    assignment = assignments_collection.find_one({
        "_id": ObjectId(assignment_id),
        "user_email": current_user.email
    })
    if not assignment:
        flash("Assignment not found.", "error")
        return redirect(url_for("search_assignment"))

    # Delete files if exist
    file_name = assignment.get("file")
    captured_file_name = assignment.get("captured_image_filename")
    if file_name:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
    if captured_file_name:
        captured_path = os.path.join(app.config['UPLOAD_FOLDER'], captured_file_name)
        if os.path.exists(captured_path):
            os.remove(captured_path)

    assignments_collection.delete_one({"_id": ObjectId(assignment_id), "user_email": current_user.email})
    flash("Assignment deleted successfully.", "success")
    return redirect(url_for("search_assignment"))
#attendance route

@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():
    user_id = current_user.get_id()

    if request.method == "POST":
        # Add a new subject
        if "new_subject" in request.form:
            subject_name = request.form.get("subject")
            db.attendance.insert_one({
                "user_id": user_id,
                "subject": subject_name,
                "date": datetime.now().strftime("%Y-%m-%d"),
                "status": "SubjectAdded"
            })
            flash("Subject added!", "success")
            return redirect(url_for("attendance"))

        # Submit attendance
        if "submit_attendance" in request.form:
            for key, value in request.form.items():
                if key.startswith("status_"):
                    subject = key.replace("status_", "")

                    # Insert only if NOT Neutral
                    if value in ["Present", "Absent"]:
                        db.attendance.insert_one({
                            "user_id": user_id,
                            "subject": subject,
                            "date": datetime.now().strftime("%Y-%m-%d"),
                            "status": value
                        })

            flash("Attendance marked!", "success")
            return redirect(url_for("attendance"))

    # ------------------- Fetch + Calculate --------------------
    subjects = db.attendance.distinct("subject", {"user_id": user_id})

    summary = []
    total_classes = 0
    total_present = 0

    for sub in subjects:
        records = list(db.attendance.find({
            "user_id": user_id,
            "subject": sub,
            "status": {"$in": ["Present", "Absent"]}
        }))
        present_count = sum(1 for r in records if r['status'] == "Present")
        class_count = len(records)
        percentage = round((present_count / class_count) * 100, 2) if class_count else 0

        total_classes += class_count
        total_present += present_count

        summary.append({
            "subject": sub,
            "present": present_count,
            "total": class_count,
            "percent": percentage
        })

    overall_percent = round((total_present / total_classes) * 100, 2) if total_classes else 0

    graph_labels = [s['subject'] for s in summary]
    graph_data  = [s['percent'] for s in summary]

    return render_template(
        "attendance.html",
        subjects=subjects,
        summary=summary,
        overall_percent=overall_percent,
        graph_labels=graph_labels,
        graph_data=graph_data
    )
#feedback
@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    feedback_text = request.form.get('feedback')
    
    if feedback_text.strip():
        feedback_data = {
            "user_email": current_user.email,
            "feedback": feedback_text,
            "timestamp": datetime.utcnow()
        }
        mongo.db.feedback.insert_one(feedback_data)
        flash("Thank you for your feedback!", "success")
    else:
        flash("Feedback cannot be empty.", "error")
    
    return redirect(url_for('profile'))

#typing test game route
@app.route("/typing_test")
@login_required
def typing_test():
    return render_template("typing_test.html")
mail = Mail(app)

# Token serializer
s = URLSafeTimedSerializer(app.secret_key)
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users.find_one({'email': email})
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            link = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request",
                          sender="your_email@gmail.com",
                          recipients=[email])
            msg.body = f"Click this link to reset your password: {link}"
            mail.send(msg)

            flash("Password reset link sent to your email.", "info")
            return redirect(url_for('login'))
        else:
            flash("Email not registered.", "danger")
    return render_template('forgot_password.html')
from werkzeug.security import generate_password_hash

serializer = URLSafeTimedSerializer(app.secret_key)

def get_email_from_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except Exception:
        return None

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = get_email_from_token(token)
    if not email:
        flash("Invalid or expired link", "danger")
        return redirect(url_for('login'))

    user_data = users.find_one({'email': email})
    if not user_data:
        flash("User not found", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        if not new_password:
            flash("Password cannot be empty", "danger")
            return redirect(request.url)

        hashed_pw = generate_password_hash(new_password)
        users.update_one(
            {'_id': user_data['_id']},
            {'$set': {'password': hashed_pw}}
        )

        flash("Password has been updated successfully! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ----------------- Run -------------------
if __name__ == "__main__":
    start_reminder_thread()   # ← start background reminder thread
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    app.run(debug=True)

