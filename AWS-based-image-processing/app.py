from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_file, g
from functools import wraps
import datetime
import os
from PIL import Image, ImageFilter, ImageEnhance
import io
import base64
import uuid
import concurrent.futures
import logging
from s3_helper import S3Helper
from dynamodb_helper import DynamoDBHelper
from cognito_helper import CognitoHelper
import sys
import boto3

# Set up logging to output to stdout (Docker captures this)
logging.basicConfig(
    level=logging.DEBUG,  # Change to DEBUG for more detailed logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'flask-super-secret-key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize AWS helpers
s3_helper = S3Helper()
db_helper = DynamoDBHelper()
cognito_helper = CognitoHelper()

# Decorator for checking user groups
def require_group(required_groups):
    """Decorator to require user to be in specific groups"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'cognito_user') or not g.cognito_user:
                return jsonify({"msg": "Authentication required"}), 401
            
            user_groups = g.cognito_user.get('cognito:groups', [])
            
            # Check if user is in any of the required groups
            if not any(group in user_groups for group in required_groups):
                return jsonify({
                    "msg": f"Access denied. Required groups: {required_groups}. Your groups: {user_groups}"
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Custom decorator for Cognito JWT verification
def cognito_jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"msg": "Missing or invalid Authorization header"}), 401
        
        token = auth_header[7:]
        try:
            # Verify using Cognito helper
            claims = cognito_helper.verify_token(token)
            # Store user info in flask.g for access in routes
            g.cognito_user = claims
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return jsonify({"msg": f"Token verification failed: {str(e)}"}), 401
    return decorated_function

# Helper function to process a single image
def process_single_image(file, filter_type, strength, size_multiplier, current_user):
    try:
        img = Image.open(file.stream)
        original_format = img.format if img.format else 'JPEG'
        
        # Apply size multiplier if needed
        if size_multiplier != 1.0:
            new_width = int(img.width * size_multiplier)
            new_height = int(img.height * size_multiplier)
            img = img.resize((new_width, new_height), Image.LANCZOS)
        
        # Apply filter with strength modifier
        if filter_type == 'BLUR':
            filtered_img = img.filter(ImageFilter.GaussianBlur(radius=strength/2))
        elif filter_type == 'CONTOUR':
            filtered_img = img
            for _ in range(strength):
                filtered_img = filtered_img.filter(ImageFilter.CONTOUR)
        elif filter_type == 'DETAIL':
            filtered_img = img
            for _ in range(strength):
                filtered_img = filtered_img.filter(ImageFilter.DETAIL)
        elif filter_type == 'EDGE_ENHANCE':
            filtered_img = img
            for _ in range(strength):
                filtered_img = filtered_img.filter(ImageFilter.EDGE_ENHANCE_MORE)
        elif filter_type == 'EMBOSS':
            filtered_img = img
            for _ in range(strength):
                filtered_img = filtered_img.filter(ImageFilter.EMBOSS)
        elif filter_type == 'SHARPEN':
            radius = max(1, strength / 3)
            percent = min(500, strength * 50)
            filtered_img = img.filter(ImageFilter.UnsharpMask(radius=radius, percent=percent, threshold=3))
        elif filter_type == 'SMOOTH':
            filtered_img = img
            for _ in range(strength):
                filtered_img = filtered_img.filter(ImageFilter.SMOOTH_MORE)
        elif filter_type == 'EDGES':
            filtered_img = img.filter(ImageFilter.FIND_EDGES)
            enhancer = ImageEnhance.Contrast(filtered_img)
            filtered_img = enhancer.enhance(strength/2)
        else:
            filtered_img = img
        
        # Generate a unique ID
        image_id = str(uuid.uuid4())
        
        # Save original image to S3
        file.stream.seek(0)  # Reset stream to beginning
        original_image_data = file.stream.read()
        s3_helper.upload_image(original_image_data, f"original_{image_id}")
        
        # Save processed image to buffer and then to S3
        img_io = io.BytesIO()
        filtered_img.save(img_io, format=original_format)
        img_io.seek(0)
        processed_image_data = img_io.getvalue()
        s3_helper.upload_image(processed_image_data, image_id, is_processed=True)
        
        # Store metadata in DynamoDB
        metadata = {
            'filename': file.filename,
            'filter': filter_type,
            'strength': strength,
            'size_multiplier': size_multiplier,
            'format': original_format.lower()
        }
        db_helper.put_image_metadata(image_id, current_user, metadata)
        
        # Generate presigned URL for the frontend
        image_url = s3_helper.generate_presigned_url(image_id, is_processed=True)
        
        return {
            "filename": file.filename,
            "message": "Image processed successfully",
            "filter": filter_type,
            "strength": strength,
            "size_multiplier": size_multiplier,
            "image_id": image_id,
            "image_url": image_url
        }
        
    except Exception as e:
        logger.error(f"Error processing image: {e}")
        return {
            "filename": file.filename,
            "error": f"Error processing image: {str(e)}"
        }

# Web interface routes
@app.route('/')
def index():
    return render_template('index.html', token=session.get('token'), current_user=session.get('username'))

@app.route('/web/login', methods=['POST'])
def web_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return render_template('index.html', error="Username and password required")
    
    result = cognito_helper.authenticate(username, password)
    
    if result['success']:
        if 'challenge' in result:
            # MFA challenge required
            session['mfa_session'] = result['session']
            session['mfa_challenge'] = result['challenge']
            session['pending_username'] = username
            return render_template('index.html', 
                                 mfa_required=True, 
                                 mfa_challenge=result['challenge'],
                                 message=result.get('message'))
        
        try:
            # Verify the token and get user claims
            claims = cognito_helper.verify_token(result['id_token'])
            
            # Use Cognito token directly (no Flask-JWT)
            session['token'] = result['id_token']
            session['access_token'] = result['access_token']
            session['cognito_token'] = result['id_token']
            session['username'] = claims.get('cognito:username', username)
            session['user_groups'] = claims.get('cognito:groups', [])
            
            return redirect(url_for('index'))
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return render_template('index.html', error="Authentication failed")
    else:
        return render_template('index.html', error="Invalid credentials")

@app.route('/web/mfa-verify', methods=['POST'])
def web_mfa_verify():
    username = session.get('pending_username')
    mfa_code = request.form.get('mfa_code')
    mfa_session = session.get('mfa_session')
    challenge_name = session.get('mfa_challenge')
    
    if not all([username, mfa_code, mfa_session, challenge_name]):
        return render_template('index.html', error="MFA verification failed - missing data")
    
    result = cognito_helper.respond_to_mfa_challenge(username, mfa_code, mfa_session, challenge_name)
    
    if result['success']:
        try:
            # Verify the token and get user claims
            claims = cognito_helper.verify_token(result['id_token'])
            
            # Clear MFA session data
            session.pop('mfa_session', None)
            session.pop('mfa_challenge', None)
            session.pop('pending_username', None)
            
            # Set authenticated session
            session['token'] = result['id_token']
            session['cognito_token'] = result['id_token']
            session['username'] = claims.get('cognito:username', username)
            session['user_groups'] = claims.get('cognito:groups', [])
            
            return redirect(url_for('index'))
            
        except Exception as e:
            logger.error(f"Token verification failed after MFA: {e}")
            return render_template('index.html', error="Authentication failed after MFA")
    else:
        return render_template('index.html', 
                             error="Invalid MFA code",
                             mfa_required=True,
                             mfa_challenge=challenge_name)

@app.route('/web/logout')
def web_logout():
    session.pop('token', None)
    session.pop('access_token', None)
    session.pop('cognito_token', None)
    session.pop('username', None)
    session.pop('user_groups', None)
    session.pop('mfa_session', None)
    session.pop('mfa_challenge', None)
    session.pop('pending_username', None)
    return redirect(url_for('index'))

@app.route('/web/test-endpoints')
@cognito_jwt_required
def web_test_endpoints():
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    return render_template('index.html', 
                         token=session.get('token'),
                         current_user=current_user,
                         test_results={"message": "Ready to test endpoints"})

# API routes
@app.route('/api/')
def api_root():
    return jsonify({"message": "Welcome to the CAB432 API Server with MFA and User Groups"})

# Cognito authentication endpoints
@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    email = request.json.get('email', None)
    user_group = request.json.get('user_group', 'Users')  # Default to Users group
    
    if not username or not password or not email:
        return jsonify({"msg": "Missing required fields"}), 400
        
    # Validate password strength (Cognito has requirements)
    if len(password) < 8:
        return jsonify({"msg": "Password must be at least 8 characters"}), 400
        
    result = cognito_helper.sign_up(username, password, email, user_group)
    
    if result['success']:
        return jsonify({
            "message": "User registered successfully. Please check your email for confirmation code.",
            "user_sub": result['user_sub'],
            "user_group": result.get('user_group')
        }), 200
    else:
        return jsonify({
            "msg": f"Sign up failed: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/auth/confirm', methods=['POST'])
def api_confirm_signup():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    username = request.json.get('username', None)
    confirmation_code = request.json.get('confirmation_code', None)
    
    if not username or not confirmation_code:
        return jsonify({"msg": "Missing username or confirmation code"}), 400
        
    result = cognito_helper.confirm_sign_up(username, confirmation_code)
    
    if result['success']:
        return jsonify({"msg": "User confirmed successfully"}), 200
    else:
        return jsonify({
            "msg": f"Confirmation failed: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
        
    result = cognito_helper.authenticate(username, password)
    
    if result['success']:
        # Check if MFA challenge is required
        if 'challenge' in result:
            return jsonify({
                "mfa_required": True,
                "challenge": result['challenge'],
                "session": result['session'],
                "message": result.get('message')
            }), 200
        
        # Verify the token to ensure it's valid
        try:
            claims = cognito_helper.verify_token(result['id_token'])
            
            return jsonify({
                "access_token": result['access_token'],
                "id_token": result['id_token'],
                "token_type": "Bearer",
                "expires_in": result['expires_in'],
                "user_groups": claims.get('cognito:groups', [])
            }), 200
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return jsonify({"msg": "Authentication failed: token verification error"}), 401
    else:
        return jsonify({
            "msg": f"Authentication failed: {result.get('error_message', 'Unknown error')}"
        }), 401

@app.route('/api/auth/mfa-verify', methods=['POST'])
def api_mfa_verify():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    username = request.json.get('username', None)
    mfa_code = request.json.get('mfa_code', None)
    session_token = request.json.get('session', None)
    challenge_name = request.json.get('challenge', 'SMS_MFA')
    
    if not all([username, mfa_code, session_token]):
        return jsonify({"msg": "Missing required MFA fields"}), 400
        
    result = cognito_helper.respond_to_mfa_challenge(username, mfa_code, session_token, challenge_name)
    
    if result['success']:
        try:
            claims = cognito_helper.verify_token(result['id_token'])
            
            return jsonify({
                "access_token": result['access_token'],
                "id_token": result['id_token'],
                "token_type": "Bearer",
                "expires_in": result['expires_in'],
                "user_groups": claims.get('cognito:groups', [])
            }), 200
            
        except Exception as e:
            logger.error(f"Token verification failed after MFA: {e}")
            return jsonify({"msg": "Authentication failed after MFA"}), 401
    else:
        return jsonify({
            "msg": f"MFA verification failed: {result.get('error_message', 'Unknown error')}"
        }), 401

@app.route('/api/auth/setup-totp', methods=['POST'])
@cognito_jwt_required
def api_setup_totp():
    """Setup TOTP (Authenticator App) using user-level API only"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"msg": "Missing access token"}), 401
    
    access_token = auth_header[7:]
    
    # Associate software token for the current user
    result = cognito_helper.associate_software_token(access_token=access_token)
    
    if result['success']:
        # Return the secret code and QR code for the user to scan
        return jsonify({
            "message": "TOTP setup initiated",
            "secret_code": result['secret_code'],
            "qr_code_data": result['qr_code_data'],
            "session_token": result.get('session_token') or access_token
        }), 200
    else:
        return jsonify({
            "msg": f"TOTP setup failed: {result.get('error_message', 'Unknown error')}"
        }), 400


@app.route('/api/auth/verify-totp-setup', methods=['POST'])
@cognito_jwt_required
def api_verify_totp_setup():
    """Verify TOTP setup with user-provided code"""
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"msg": "Missing access token"}), 401
    
    access_token = auth_header[7:]
    user_code = request.json.get('user_code', None)
    session_token = request.json.get('session_token', None)
    
    if not user_code or not session_token:
        return jsonify({"msg": "Missing user code or session"}), 400
    
    result = cognito_helper.verify_software_token(
        user_code=user_code,
        access_token=access_token,
        session=session_token
    )
    
    if result['success']:
        return jsonify({
            "message": "TOTP verified successfully",
            "status": result['status']
        }), 200
    else:
        return jsonify({
            "msg": f"TOTP verification failed: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/auth/userinfo', methods=['GET'])
@cognito_jwt_required
def api_user_info():
    try:
        # Get user info from Cognito
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            cognito_token = auth_header[7:]
            user_info = cognito_helper.get_user_info(cognito_token)
            return jsonify(user_info), 200
        else:
            return jsonify({"msg": "Authorization header missing or invalid"}), 401
    except Exception as e:
        logger.error(f"Failed to get user info: {e}")
        return jsonify({"msg": "Failed to retrieve user information"}), 500

@app.route('/api/protected', methods=['GET'])
@cognito_jwt_required
def api_protected():
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    user_groups = g.cognito_user.get('cognito:groups', [])
    
    # Try to get additional info from Cognito if available
    cognito_info = {}
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        try:
            cognito_token = auth_header[7:]
            cognito_info = cognito_helper.get_user_info(cognito_token)
        except:
            pass  # Fall back to basic info
    
    return jsonify({
        "logged_in_as": current_user,
        "user_groups": user_groups,
        "cognito_info": cognito_info,
        "message": "This is a protected endpoint"
    }), 200

# Admin endpoints (require Admin group)
@app.route('/api/admin/users/<username>/groups', methods=['POST'])
@cognito_jwt_required
@require_group(['Admins'])
def api_add_user_to_group(username):
    """Add user to a group (Admin only)"""
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    group_name = request.json.get('group_name')
    if not group_name:
        return jsonify({"msg": "Missing group_name"}), 400
    
    result = cognito_helper.add_user_to_group(username, group_name)
    
    if result['success']:
        return jsonify({"message": f"User {username} added to group {group_name}"}), 200
    else:
        return jsonify({
            "msg": f"Failed to add user to group: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/admin/users/<username>/groups/<group_name>', methods=['DELETE'])
@cognito_jwt_required
@require_group(['Admins'])
def api_remove_user_from_group(username, group_name):
    """Remove user from a group (Admin only)"""
    result = cognito_helper.remove_user_from_group(username, group_name)
    
    if result['success']:
        return jsonify({"message": f"User {username} removed from group {group_name}"}), 200
    else:
        return jsonify({
            "msg": f"Failed to remove user from group: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/admin/users/<username>/mfa', methods=['POST'])
@cognito_jwt_required
@require_group(['Admins'])
def api_enable_user_mfa(username):
    """Enable MFA for a user (Admin only)"""
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    mfa_type = request.json.get('mfa_type', 'SMS_MFA')
    
    result = cognito_helper.enable_mfa_for_user(username, mfa_type)
    
    if result['success']:
        return jsonify({
            "message": f"MFA ({mfa_type}) enabled for user {username}",
            "mfa_type": result['mfa_type']
        }), 200
    else:
        return jsonify({
            "msg": f"Failed to enable MFA: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/admin/groups', methods=['GET'])
@cognito_jwt_required
@require_group(['Admins'])
def api_list_groups():
    """List all groups (Admin only)"""
    result = cognito_helper.list_all_groups()
    
    if result['success']:
        return jsonify({
            "groups": result['groups'],
            "count": len(result['groups'])
        }), 200
    else:
        return jsonify({
            "msg": f"Failed to list groups: {result.get('error_message', 'Unknown error')}"
        }), 400

@app.route('/api/users/groups', methods=['GET'])
@cognito_jwt_required
def api_get_my_groups():
    """Get current user's groups"""
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    user_groups = g.cognito_user.get('cognito:groups', [])
    
    return jsonify({
        "username": current_user,
        "groups": user_groups
    }), 200

# Premium endpoint (require Premium group)
@app.route('/api/premium/batch-process-large', methods=['POST'])
@cognito_jwt_required
@require_group(['Premium', 'Admins'])
def api_premium_batch_process():
    """Batch processing for Premium users"""
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    
    # This could be batch processing with higher limits, priority processing, etc.
    return jsonify({
        "message": "Premium batch processing initiated",
        "user": current_user,
        "features": ["Priority queue", "Higher batch limits", "Advanced filters"]
    }), 200

@app.route('/api/process', methods=['POST'])
@cognito_jwt_required
def api_process():
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    user_groups = g.cognito_user.get('cognito:groups', [])
    
    # Different processing based on user group
    processing_time = 2  # Default
    if 'Premium' in user_groups:
        processing_time = 1  # Faster for premium users
    elif 'Admins' in user_groups:
        processing_time = 0.5  # Fastest for admins
    
    import time
    time.sleep(processing_time)
    
    return jsonify({
        "message": "Processing complete", 
        "user": current_user,
        "user_groups": user_groups,
        "processing_time": processing_time,
        "result": "Sample processed data"
    }), 200

@app.route('/api/filter-image', methods=['POST'])
@cognito_jwt_required
def api_filter_image():
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    user_groups = g.cognito_user.get('cognito:groups', [])
    
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400
    
    file = request.files['image']
    filter_type = request.form.get('filter', 'BLUR')
    strength = int(request.form.get('strength', 5))
    size_multiplier = float(request.form.get('size_multiplier', 1.0))
    
    # Check size limits based on user group
    max_size_multiplier = 2.0  # Default for Users
    if 'Premium' in user_groups:
        max_size_multiplier = 10.0
    elif 'Admins' in user_groups:
        max_size_multiplier = 20.0
    
    if size_multiplier > max_size_multiplier:
        return jsonify({
            "error": f"Size multiplier {size_multiplier} exceeds limit for your group. Max: {max_size_multiplier}"
        }), 403
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        result = process_single_image(file, filter_type, strength, size_multiplier, current_user)
        
        if 'error' in result:
            return jsonify({"error": result['error']}), 500
        else:
            return jsonify({
                "message": "Image processed successfully",
                "user": current_user,
                "user_groups": user_groups,
                "filter": result['filter'],
                "strength": result['strength'],
                "size_multiplier": result['size_multiplier'],
                "image_id": result['image_id'],
                "image_url": result['image_url']
            }), 200

@app.route('/api/batch-filter-images', methods=['POST'])
@cognito_jwt_required
def api_batch_filter_images():
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))
    user_groups = g.cognito_user.get('cognito:groups', [])
    
    if 'images' not in request.files:
        return jsonify({"error": "No image files provided"}), 400
    
    uploaded_files = request.files.getlist('images')
    filter_type = request.form.get('filter', 'BLUR')
    strength = int(request.form.get('strength', 5))
    size_multiplier = float(request.form.get('size_multiplier', 1.0))
    
    # Check batch limits based on user group
    max_batch_size = 5  # Default for Users
    if 'Premium' in user_groups:
        max_batch_size = 20
    elif 'Admins' in user_groups:
        max_batch_size = 50
    
    if len(uploaded_files) > max_batch_size:
        return jsonify({
            "error": f"Batch size {len(uploaded_files)} exceeds limit for your group. Max: {max_batch_size}"
        }), 403
    
    if not uploaded_files or uploaded_files[0].filename == '':
        return jsonify({"error": "No selected files"}), 400
    
    results = []
    
    # Process images in parallel using ThreadPoolExecutor
    max_workers = 5  # Default
    if 'Premium' in user_groups:
        max_workers = 10
    elif 'Admins' in user_groups:
        max_workers = 15
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a list of futures
        futures = []
        for file in uploaded_files:
            if file and file.filename != '':
                # Reset file stream position to ensure each thread gets a fresh copy
                file.stream.seek(0)
                futures.append(
                    executor.submit(
                        process_single_image, 
                        file, 
                        filter_type, 
                        strength, 
                        size_multiplier, 
                        current_user
                    )
                )
        
        # Wait for all futures to complete and collect results
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    "filename": "Unknown",
                    "error": f"Error processing image: {str(e)}"
                })
    
    return jsonify({
        "user": current_user,
        "user_groups": user_groups,
        "max_batch_size": max_batch_size,
        "max_workers": max_workers,
        "processed_count": len([r for r in results if 'error' not in r]),
        "error_count": len([r for r in results if 'error' in r]),
        "results": results
    }), 200

@app.route('/api/my-images', methods=['GET'])
@cognito_jwt_required
def api_my_images():
    current_user = g.cognito_user.get('cognito:username', g.cognito_user.get('username'))

    # Get user's images from DynamoDB
    user_images = db_helper.get_user_images(current_user)

    # Generate presigned URLs for each image
    images_with_urls = []
    for img in user_images:
        image_url = s3_helper.generate_presigned_url(img['ImageID'], is_processed=True)
        images_with_urls.append({
            "image_id": img['ImageID'],
            "filter": img['Filter'],
            "strength": img['Strength'],
            "size_multiplier": img['SizeMultiplier'],
            "image_url": image_url
        })

    return jsonify(images_with_urls), 200

@app.route('/api/download-image/<image_id>', methods=['GET'])
def api_download_image(image_id):
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Missing token"}), 401
    
    try:
        claims = cognito_helper.verify_token(token)
    except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return jsonify({"error": "Invalid token"}), 401
        
    # Get image directly from S3
    image_data = s3_helper.download_image(image_id, is_processed=True)
    
    if not image_data:
        return jsonify({"error": "Image not found"}), 404
    
    # Get metadata from DynamoDB for filename
    metadata = db_helper.get_image_metadata(image_id)
    
    if metadata:
        filter_name = metadata['filter']
        format = metadata['format']
        filename = f"filtered_image_{filter_name.lower()}.{format}"
    else:
        filename = f"filtered_image.{image_id.split('.')[-1] if '.' in image_id else 'jpg'}"
    
    # Create in-memory file and send
    img_io = io.BytesIO(image_data)
    img_io.seek(0)
    
    return send_file(
        img_io,
        mimetype=f"image/{format if metadata else 'jpeg'}",
        as_attachment=True,
        download_name=filename
    )

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint to verify all services including Cognito"""
    try:
        # Test S3 connectivity
        s3_test = s3_helper.image_exists("test", is_processed=False)
        
        # Test DynamoDB connectivity
        db_test = db_helper.get_image_metadata("test")
        
        # Test Cognito connectivity and features
        cognito_connected = False
        groups_available = False
        mfa_supported = False
        
        try:
            # Test basic connectivity
            cognito_helper._get_jwks()
            cognito_connected = True
            
            # Test groups functionality
            groups_result = cognito_helper.list_all_groups()
            if groups_result.get('success'):
                groups_available = True
                logger.info(f"Found {len(groups_result['groups'])} Cognito groups")
            
            # Check if user pool supports MFA (basic check)
            try:
                # This will work if the user pool is configured for MFA
                user_pool_client = boto3.client('cognito-idp', region_name='ap-southeast-2')
                pool_info = user_pool_client.describe_user_pool(UserPoolId=cognito_helper.user_pool_id)
                mfa_config = pool_info['UserPool'].get('MfaConfiguration', 'OFF')
                mfa_supported = mfa_config in ['OPTIONAL', 'ON']
                logger.info(f"MFA configuration: {mfa_config}")
            except Exception as mfa_e:
                logger.warning(f"Could not check MFA configuration: {mfa_e}")
            
        except Exception as e:
            logger.error(f"Cognito connectivity test failed: {e}")
        
        return jsonify({
            "status": "healthy",
            "s3_connected": True,
            "dynamodb_connected": True,
            "cognito_connected": cognito_connected,
            "features": {
                "user_groups": "enabled" if groups_available else "limited",
                "mfa": "enabled" if mfa_supported else "basic",
                "group_based_limits": "enabled"
            },
            "cognito_groups": groups_result.get('groups', []) if groups_available else [],
            "timestamp": datetime.datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        
    app.run(debug=True, host='0.0.0.0', port=8080)