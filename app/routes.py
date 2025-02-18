from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify, send_file, Response, stream_with_context
from flask_login import login_user, logout_user, login_required, current_user
from app import db, mail
from app.models import User, File
from app.forms import LoginForm, RegistrationForm, FileUploadForm
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import os
import logging
import json
import queue
import threading
from datetime import datetime

load_dotenv()
csrf = CSRFProtect()
main = Blueprint('main', __name__)

logging.basicConfig(level=logging.DEBUG)  # Add this for better debugging

# Create a message queue for events
message_queue = queue.Queue()

# Create a global event listeners list
listeners = []

def format_sse(data, event=None):
    """Format data for SSE"""
    msg = f"data: {json.dumps(data)}\n\n"
    if event is not None:
        msg = f"event: {event}\n{msg}"
    return msg

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
    try:
        token = generate_token(user.email)
        verification_url = url_for('main.verify_email', token=token, _external=True)
        
        msg = Message('Please verify your email',
                     sender=current_app.config['MAIL_DEFAULT_SENDER'],
                     recipients=[user.email])
        
        msg.body = f"""
        Welcome to our file sharing platform!
        
        Please click the following link to verify your account:
        {verification_url}
        
        If you did not register for this account, please ignore this email.
        
        This link will expire in 1 hour.
        """
        
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Failed to send verification email: {str(e)}")
        return False

@main.route('/index')
@login_required
def index():
    files = File.query.all()
    form = FileUploadForm()
    return render_template('index.html', files=files, form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            # Only check verification for ISOPS users
            if user.is_ops and not user.is_verified:
                flash('ISOPS users must verify their email before logging in.', 'warning')
                return redirect(url_for('main.login'))
            
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('main.index'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Get the isops value from the form
            is_ops = request.form.get('isops') == 'yes'
            
            # Create new user
            user = User(
                email=form.email.data,
                is_ops=is_ops,
                # Set is_verified to True for normal users, False for ISOPS
                is_verified=not is_ops
            )
            user.set_password(form.password.data)
            
            # Add user to database
            db.session.add(user)
            db.session.commit()
            
            # Only send verification email for ISOPS users
            if is_ops:
                try:
                    send_verification_email(user)
                    flash('Registration successful! Please check your email to verify your account.', 'success')
                except Exception as e:
                    db.session.rollback()
                    logging.error(f"Failed to send verification email: {str(e)}")
                    flash(f'Registration successful, but email verification failed: {str(e)}', 'warning')
            else:
                flash('Registration successful! You can now login.', 'success')
            
            return redirect(url_for('main.login'))
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Registration error: {str(e)}")
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template('register.html', form=form)
    
    # If form validation failed, show the errors
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')
    
    return render_template('register.html', form=form)

@main.route('/verify/<token>')
def verify_email(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        user = User.query.filter_by(email=email).first_or_404()
        
        if user.is_verified:
            flash('Email already verified. Please login.', 'info')
        else:
            user.is_verified = True
            db.session.commit()
            flash('Email verified successfully! You can now login.', 'success')
            
        return redirect(url_for('main.login'))
    except Exception as e:
        flash('The verification link is invalid or has expired.', 'error')
        return redirect(url_for('main.login'))

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if not current_user.is_ops:
        flash('Only ISOPS users can upload files.', 'error')
        return redirect(url_for('main.index'))
    
    form = FileUploadForm()
    
    if form.validate_on_submit():
        try:
            file = form.file.data
            filename = secure_filename(file.filename)
            
            # Get the absolute path to the uploads directory
            uploads_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
            
            # Create uploads directory if it doesn't exist
            if not os.path.exists(uploads_dir):
                os.makedirs(uploads_dir)
            
            # Save the file
            file_path = os.path.join(uploads_dir, filename)
            file.save(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Create new file record
            new_file = File(
                filename=filename,
                file_path=file_path,
                file_size=file_size,
                upload_date=datetime.utcnow(),
                uploaded_by=current_user.id,
                download_count=0
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            # Notify clients about the new file
            notify_clients({
                'type': 'refresh',
                'action': 'upload',
                'file_id': new_file.id
            })
            
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('main.show_files'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading file: {str(e)}', 'error')
    
    return render_template('upload.html', form=form)

@main.route('/logout', methods=['POST'])
@csrf.exempt
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

def is_valid_file_type(filename):
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/files')
@login_required
def show_files():
    # For ISOPS users, show only their uploaded files
    if current_user.is_ops:
        files = File.query.filter_by(uploaded_by=current_user.id).order_by(File.upload_date.desc()).all()
        total_downloads = sum(file.download_count for file in files)
        total_size = sum(file.file_size or 0 for file in files)
        show_stats = True
    else:
        # For normal users, show all files
        files = File.query.order_by(File.upload_date.desc()).all()
        show_stats = False
        total_downloads = None
        total_size = None
    
    return render_template('files.html', 
                         files=files, 
                         show_stats=show_stats,
                         total_downloads=total_downloads,
                         total_size=total_size)

@main.route('/stream')
def stream():
    def event_stream():
        # Create a new listener queue for this client
        client_queue = []
        listeners.append(client_queue)
        
        try:
            while True:
                # Check if there are any messages
                if client_queue:
                    msg = client_queue.pop(0)
                    yield format_sse(msg)
                else:
                    # Send a heartbeat every 30 seconds
                    yield format_sse({"type": "heartbeat", "time": str(datetime.now())})
                    
        except GeneratorExit:
            # Remove this client's queue when they disconnect
            listeners.remove(client_queue)

    return Response(
        stream_with_context(event_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

def notify_clients(data):
    """Send data to all connected clients"""
    refresh_data = {
        'type': 'refresh',
        'action': data.get('action'),
        'file_id': data.get('file_id')
    }
    for queue in listeners:
        queue.append(refresh_data)

@main.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.uploaded_by != current_user.id and not current_user.is_ops:
        flash('You do not have permission to delete this file.', 'error')
        return redirect(url_for('main.show_files'))
    
    try:
        # Get file info before deletion
        file_info = {
            'type': 'file_update',
            'action': 'delete',
            'file_id': file.id
        }
        
        # Delete file
        uploads_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
        file_path = os.path.join(uploads_dir, secure_filename(file.filename))
        
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(file)
        db.session.commit()
        
        # Notify all clients
        notify_clients(file_info)
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@main.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    try:
        # Increment download count
        file.download_count += 1
        db.session.commit()
        
        # Notify all clients about the download
        notify_clients({
            'type': 'file_update',
            'action': 'download',
            'file_id': file.id,
            'download_count': file.download_count
        })
        
        # Return file
        uploads_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
        file_path = os.path.join(uploads_dir, secure_filename(file.filename))
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file.filename
        )
    except Exception as e:
        db.session.rollback()
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('main.show_files'))

# Add file search functionality
@main.route('/search')
@login_required
def search_files():
    query = request.args.get('query', '')
    
    # Base query
    if current_user.is_ops:
        # ISOPS users can only search their own files
        base_query = File.query.filter_by(uploaded_by=current_user.id)
    else:
        # Normal users can search all files
        base_query = File.query
    
    # Apply search filter
    if query:
        search = f"%{query}%"
        files = base_query.filter(File.filename.ilike(search)).order_by(File.upload_date.desc()).all()
    else:
        files = base_query.order_by(File.upload_date.desc()).all()
    
    # Calculate stats for ISOPS users
    if current_user.is_ops:
        total_downloads = sum(file.download_count for file in files)
        total_size = sum(file.file_size or 0 for file in files)
        show_stats = True
    else:
        show_stats = False
        total_downloads = None
        total_size = None
    
    return render_template('files.html', 
                         files=files, 
                         search_query=query,
                         show_stats=show_stats,
                         total_downloads=total_downloads,
                         total_size=total_size)

@main.route('/api/file/<int:file_id>')
@login_required
def get_file_info(file_id):
    try:
        file = File.query.get_or_404(file_id)
        return jsonify({
            'success': True,
            'download_count': file.download_count
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main.route('/api/refresh-data')
@login_required
def refresh_data():
    try:
        if current_user.is_ops:
            # For ISOPS users, show only their uploaded files
            files = File.query.filter_by(uploaded_by=current_user.id).order_by(File.upload_date.desc()).all()
            total_downloads = sum(file.download_count for file in files)
            total_size = sum(file.file_size or 0 for file in files)
        else:
            # For normal users, show all files
            files = File.query.order_by(File.upload_date.desc()).all()
            total_downloads = None
            total_size = None

        files_data = [{
            'id': file.id,
            'filename': file.filename,
            'upload_date': file.upload_date.strftime('%Y-%m-%d %H:%M'),
            'file_size': file.file_size,
            'download_count': file.download_count,
            'uploaded_by': file.uploaded_by,
            'uploader_email': User.query.get(file.uploaded_by).email if file.uploaded_by else 'Unknown'
        } for file in files]

        return jsonify({
            'success': True,
            'files': files_data,
            'total_downloads': total_downloads,
            'total_size': total_size,
            'total_files': len(files)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500










