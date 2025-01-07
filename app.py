import joblib
import requests
import os
from flask import Flask, render_template, request, make_response, redirect, url_for, flash, session
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
csrf = CSRFProtect(app)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'phishshield.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Configure Flask-Caching to use on-disk caching
cache_dir = os.path.join(app.root_path, '.cache')
cache = Cache(app, config={'CACHE_TYPE': 'filesystem', 'CACHE_DIR': cache_dir})

# Configure reCAPTCHA keys
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# Define database models for Contact and User
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Load the trained model
feature_model = joblib.load("models/feature_model.joblib")

@app.route('/admin_login', methods=['GET', 'POST'])
@csrf.exempt
def admin_login():
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('view_contacts'))
        else:
            flash('Incorrect password. Please try again.', 'danger')
    return render_template('admin_login.html')

# Admin logout route
@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

def verify_recaptcha(token):
    """Helper function to verify reCAPTCHA token with Google."""
    response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={'secret': RECAPTCHA_SECRET_KEY, 'response': token}
    )
    if response.ok:
        result = response.json()
        return result.get('success', False)
    return False

@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Validate reCAPTCHA
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            flash("Please complete the reCAPTCHA.", "danger")
            return render_template('register.html', RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

        # Validate passwords
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.", "danger")
            return render_template('register.html', RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

        # Hash password and save new user
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Authenticate user
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            # Set session and redirect to home page
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login successful!", "success")
            return redirect(url_for('detect_phishing'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@csrf.exempt
def detect_phishing():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        url = request.form["url"]
        
        # Check if the result is cached
        cached_result = cache.get(url)
        if cached_result:
            return cached_result

        try:
            response = requests.get(url, timeout=5, verify=True)
            if response.status_code == 200:
                feature_pred = feature_model.predict([url])[0]
                feature_confidence = feature_model.predict_proba([url])[0]
                confidence_phishing_feature = feature_confidence[0] * 100
                confidence_legitimate_feature = feature_confidence[1] * 100
                threshold = 55
                final_pred = -1 if confidence_phishing_feature > threshold else 1
                result = "Phishing" if final_pred == -1 else "Legitimate"
            else:
                result = "Phishing"
                confidence_phishing_feature = 100.0
                confidence_legitimate_feature = 0.0
        except requests.exceptions.SSLError:
            result = "Phishing"
            confidence_phishing_feature = 100.0
            confidence_legitimate_feature = 0.0
        except requests.RequestException:
            result = "Phishing"
            confidence_phishing_feature = 100.0
            confidence_legitimate_feature = 0.0

        cached_render = render_template(
            'index.html',
            url=url,
            result=result,
            confidence_phishing_feature=confidence_phishing_feature,
            confidence_legitimate_feature=confidence_legitimate_feature
        )
        cache.set(url, cached_render, timeout=86400)
        return cached_render

    return render_template('index.html')

@app.route('/how_it_works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/contact', methods=['GET'])
def contact():
    return render_template('contact.html')

@app.route('/submit_contact', methods=['POST'])
@csrf.exempt
def submit_contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    new_contact = Contact(name=name, email=email, message=message)
    db.session.add(new_contact)
    db.session.commit()

    return render_template('contact.html', success=True)

@app.route('/view_contacts', methods=['GET'])
def view_contacts():
    if not session.get('admin_logged_in'):
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('admin_login'))

    contacts = Contact.query.all()
    return render_template('view_contacts.html', contacts=contacts)

@app.route('/delete_contact/<int:id>', methods=['POST'])
@csrf.exempt
def delete_contact(id):
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    flash('Contact deleted successfully.', 'success')
    return redirect(url_for('view_contacts'))

@app.route('/faq', methods=['GET'])
def faq():
    return render_template('faq.html')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
