from flask import Blueprint, render_template, session, request, redirect, url_for, flash
from auth.firebase_communicator import firebase_auth
from database.database_communicator import DatabaseCommunicator
from auth.extensions import limiter

auth_bp = Blueprint('auth', __name__)
auth = firebase_auth()
db = DatabaseCommunicator()

def is_logged_in():
    return 'uid' in session

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            return render_template('auth/login.html', error='Email and password are required')
        
        result = auth.sign_in(email, password)
        
        if result['success']:
            session['uid'] = result['uid']
            session['email'] = result['email']
            session['id_token'] = result['id_token']
            session['refresh_token'] = result['refresh_token']
            return redirect(url_for('index'))
        else:
            return render_template('auth/login.html', error=result['error'])
    
    return render_template('auth/login.html')

@auth_bp.route('/logout', methods=['GET'])
@limiter.limit("30 per minute")
def logout():
    session.clear()
    return redirect(url_for('index'))

@auth_bp.route('/create_account', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def create_account():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not email or not password or not confirm_password:
            return render_template('auth/create_account.html', error='All fields are required')
        
        if password != confirm_password:
            return render_template('auth/create_account.html', error='Passwords do not match')
        
        if len(password) < 6:
            return render_template('auth/create_account.html', error='Password must be at least 6 characters')
        
        result = auth.create_user(email, password)
        
        if result['success']:
            # Create database entry for the user
            db_result = db.create_user_entry(result['uid'], email)
            
            session['uid'] = result['uid']
            session['email'] = result['email']
            session['id_token'] = result['id_token']
            # Send email verification
            auth.send_email_verification(result['id_token'])
            return redirect(url_for('index'))
        else:
            return render_template('auth/create_account.html', error=result['error'])
    
    return render_template('auth/create_account.html')

@auth_bp.route('/settings', methods=['GET'])
def settings():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user_info = auth.get_user_info(session['id_token'])
    return render_template(
        'settings.html',
        user=user_info if user_info['success'] else {},
        error=request.args.get('error'),
        success=request.args.get('success')
    )

@auth_bp.route('/change_email', methods=['POST'])
@limiter.limit("5 per minute")
def change_email():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    new_email = request.form.get('new_email')
    
    if not new_email:
        return redirect(url_for('auth.settings', error='Email is required'))
    
    result = auth.change_email(session['id_token'], new_email)
    
    if result['success']:
        session['email'] = new_email
        # Auto send email verification
        auth.send_email_verification(session['id_token'])
        return redirect(url_for('auth.settings', success='Email changed. Verification email sent!'))
    else:
        return redirect(url_for('auth.settings', error=result['error']))

@auth_bp.route('/change_password', methods=['POST'])
@limiter.limit("5 per minute")
def change_password():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not new_password or not confirm_password:
        return redirect(url_for('auth.settings', error='All fields are required'))
    
    if new_password != confirm_password:
        return redirect(url_for('auth.settings', error='Passwords do not match'))
    
    if len(new_password) < 6:
        return redirect(url_for('auth.settings', error='Password must be at least 6 characters'))
    
    result = auth.change_password(session['id_token'], new_password)
    
    if result['success']:
        return redirect(url_for('auth.settings', success='Password changed successfully'))
    else:
        return redirect(url_for('auth.settings', error=result['error']))

@auth_bp.route('/resend_verification_email', methods=['POST'])
@limiter.limit("3 per minute")
def resend_verification_email():
    if not is_logged_in():
        return redirect(url_for('auth.login'))

    user_info = auth.get_user_info(session['id_token'])
    if not user_info.get('success'):
        return redirect(url_for('auth.settings', error='Unable to load account information'))

    if user_info.get('email_verified'):
        return redirect(url_for('auth.settings', success='Email is already verified'))

    result = auth.send_email_verification(session['id_token'])

    if result['success']:
        return redirect(url_for('auth.settings', success='Verification email sent'))
    return redirect(url_for('auth.settings', error=result['error']))

@auth_bp.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            return render_template('auth/reset_password.html', error='Email is required')
        
        result = auth.reset_password(email)
        
        if result['success']:
            return render_template('auth/reset_password.html', success='Password reset email sent')
        else:
            return render_template('auth/reset_password.html', error=result['error'])
    
    return render_template('auth/reset_password.html')

@auth_bp.route('/delete_account', methods=['POST'])
@limiter.limit("3 per minute")
def delete_account():
    if not is_logged_in():
        return redirect(url_for('auth.login'))
    
    uid = session.get('uid')
    id_token = session.get('id_token')
    
    # Delete from Firebase
    result = auth.delete_user(id_token)
    
    if result['success']:
        # Delete from database
        db.delete_user_entry(uid)
        session.clear()
        return redirect(url_for('index', success='Account deleted successfully'))
    else:
        return redirect(url_for('auth.settings', error=result['error']))