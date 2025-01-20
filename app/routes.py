from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db, mail
from app.models import User, File
from app.forms import LoginForm, RegistrationForm, FileUploadForm
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from flask_wtf.csrf import CSRFProtect
import os
csrf = CSRFProtect()
main = Blueprint('main', __name__)

# Password Hashing
def hash_password(password):
    return generate_password_hash(password)

def check_password(input_password, hashed_password):
    return check_password_hash(hashed_password, input_password)

# Generate Token
def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

# Email Verification
def send_verification_email(user):
    token = generate_token(user.email)
    verification_url = url_for('main.verify_email', token=token, _external=True)
    msg = Message('Please verify your email', sender='chaitanyagrawal1970@gmail.com', recipients=[user.email])
    msg.body = f"Click the link to verify your account: {verification_url}"
    mail.send(msg)

@main.route('/index')
@login_required
def index():
    files = File.query.all()
    form = FileUploadForm()
    return render_template('index.html', files=files, form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password(form.password.data, user.password):
            login_user(user)
            return redirect(url_for('main.index'))
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@main.route('/register', methods=['GET', 'POST'])
@main.route('/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Capture the 'isops' value from the form
        isops = request.form.get('isops', False)  # Default to 'no' if not provided

        # Ensure 'isops' is processed correctly
        if isops not in [True, False]:
            isops = False  # Default fallback
        user = User(email=form.email.data, password=hash_password(form.password.data),is_ops = isops)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash('Check your email to verify your account.')
        return redirect(url_for('main.login'))
    return render_template('login.html', form=form)

@main.route('/verify/<token>')
def verify_email(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        user = User.query.filter_by(email=email).first_or_404()
        user.is_verified = True
        db.session.commit()
        flash('Email verified successfully!')
        return redirect(url_for('main.index'))
    except Exception:
        flash('Verification link is invalid or expired.')
        return redirect(url_for('main.index'))

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if not current_user.is_ops:
        return jsonify({"msg": "Only ops users can upload files"}), 403
    form = FileUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if is_valid_file_type(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            db_file = File(filename=filename, file_path=file_path, uploaded_by=current_user.id)
            db.session.add(db_file)
            db.session.commit()
            return redirect(url_for('main.index'))
        flash('Invalid file type.')
    return render_template('upload.html', form=form)

@main.route('/logout', methods=['POST'])
@csrf.exempt
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

def is_valid_file_type(filename):
    valid_extensions = ['.pptx', '.docx', '.xlsx']
    return any(filename.endswith(ext) for ext in valid_extensions)

@main.route('/files')
@login_required
def show_files():
    # Only non-ops users are allowed to view files
    if current_user.is_ops:
        flash("Ops users cannot view files.")
        return redirect(url_for('main.index'))

    # Fetch files uploaded by other users
    files = File.query.all()
    return render_template('files.html', files=files)










