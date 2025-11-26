import boto3
import hmac
import hashlib
import base64
import json
import logging
from botocore.exceptions import ClientError
from jose import jwt
import requests
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

class CognitoHelper:
    def __init__(self):
        try:
            self.region = 'ap-southeast-2'
            self.user_pool_id = os.environ.get('COGNITO_USER_POOL_ID')
            self.client_id = os.environ.get('COGNITO_CLIENT_ID')
            self.client_secret = os.environ.get('COGNITO_CLIENT_SECRET')
            
            if not all([self.user_pool_id, self.client_id]):
                raise ValueError("Cognito configuration missing. Set COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID environment variables.")
            
            self.cognito_client = boto3.client('cognito-idp', region_name=self.region)
            self.jwks_url = f'https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json'
            
            # Cache for JWKS
            self.jwks = None
            self.jwks_last_fetch = None
            
            logger.info("Cognito helper initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Cognito helper: {e}")
            raise

    def _get_secret_hash(self, username):
        """Calculate secret hash for Cognito authentication"""
        message = username + self.client_id
        dig = hmac.new(
            self.client_secret.encode('utf-8') if self.client_secret else b'',
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(dig).decode()

    def _get_jwks(self):
        """Get JWKS with caching"""
        if self.jwks is None or (self.jwks_last_fetch and 
                                datetime.now() - self.jwks_last_fetch > timedelta(hours=1)):
            try:
                response = requests.get(self.jwks_url, timeout=10)
                response.raise_for_status()
                self.jwks = response.json()
                self.jwks_last_fetch = datetime.now()
                logger.info("JWKS fetched successfully")
            except Exception as e:
                logger.error(f"Failed to fetch JWKS: {e}")
                raise
        return self.jwks



    def sign_up(self, username, password, email, user_group='Users'):
        """Register a new user and optionally add to a group"""
        try:
            sign_up_params = {
                'ClientId': self.client_id,
                'Username': username,
                'Password': password,
                'UserAttributes': [
                    {
                        'Name': 'email',
                        'Value': email
                    }
                ]
            }
            
            # Add secret hash if client secret is configured
            if self.client_secret:
                sign_up_params['SecretHash'] = self._get_secret_hash(username)
            
            response = self.cognito_client.sign_up(**sign_up_params)
            
            # Add user to group after successful signup
            if user_group:
                try:
                    self.add_user_to_group(username, user_group)
                    logger.info(f"User {username} added to group {user_group}")
                except Exception as e:
                    logger.warning(f"Failed to add user to group: {e}")
            
            logger.info(f"User {username} signed up successfully")
            return {
                'success': True,
                'user_sub': response['UserSub'],
                'code_delivery_details': response['CodeDeliveryDetails'],
                'user_group': user_group
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Sign up failed: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def confirm_sign_up(self, username, confirmation_code):
        """Confirm user registration with code from email"""
        try:
            confirm_params = {
                'ClientId': self.client_id,
                'Username': username,
                'ConfirmationCode': confirmation_code
            }
            
            # Add secret hash if client secret is configured
            if self.client_secret:
                confirm_params['SecretHash'] = self._get_secret_hash(username)
            
            self.cognito_client.confirm_sign_up(**confirm_params)
            
            logger.info(f"User {username} confirmed successfully")
            return {'success': True}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Confirmation failed: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def authenticate(self, username, password):
        """Authenticate user and return JWT tokens"""
        try:
            auth_params = {
                'AuthFlow': 'USER_PASSWORD_AUTH',
                'ClientId': self.client_id,
                'AuthParameters': {
                    'USERNAME': username,
                    'PASSWORD': password
                }
            }
            
            # Add secret hash if client secret is configured
            if self.client_secret:
                auth_params['AuthParameters']['SECRET_HASH'] = self._get_secret_hash(username)
            
            response = self.cognito_client.initiate_auth(**auth_params)
            
            # Handle MFA challenge if present
            if 'ChallengeName' in response:
                challenge_name = response['ChallengeName']
                session = response['Session']
                
                if challenge_name == 'SOFTWARE_TOKEN_MFA':
                    return {
                        'success': True,
                        'challenge': 'SOFTWARE_TOKEN_MFA',
                        'session': session,
                        'message': 'Please enter your TOTP code from your authenticator app.'
                    }
                else:
                    return {
                        'success': False,
                        'error_message': f'Unsupported challenge: {challenge_name}'
                    }
            
            tokens = response['AuthenticationResult']
            
            logger.info(f"User {username} authenticated successfully")
            return {
                'success': True,
                'access_token': tokens['AccessToken'],
                'id_token': tokens['IdToken'],
                'refresh_token': tokens['RefreshToken'],
                'expires_in': tokens['ExpiresIn']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Authentication failed: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def respond_to_mfa_challenge(self, username, mfa_code, session, challenge_name='SOFTWARE_TOKEN_MFA'):
        """Respond to MFA challenge with verification code"""
        try:
            challenge_responses = {
                'USERNAME': username,
                'SOFTWARE_TOKEN_MFA_CODE': mfa_code
            }
            
            if self.client_secret:
                challenge_responses['SECRET_HASH'] = self._get_secret_hash(username)
            
            response = self.cognito_client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName=challenge_name,
                Session=session,
                ChallengeResponses=challenge_responses
            )
            
            tokens = response['AuthenticationResult']
            
            logger.info(f"MFA challenge completed for user {username}")
            return {
                'success': True,
                'access_token': tokens['AccessToken'],
                'id_token': tokens['IdToken'],
                'refresh_token': tokens['RefreshToken'],
                'expires_in': tokens['ExpiresIn']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"MFA challenge failed: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def enable_mfa_for_user(self, username):
        """Enable SOFTWARE_TOKEN_MFA for a user (admin function)"""
        try:
            self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SoftwareTokenMfaSettings={
                    'Enabled': True,
                    'PreferredMfa': True
                }
            )
            logger.info(f"SOFTWARE_TOKEN_MFA enabled for user {username}")
            return {'success': True}
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to enable SOFTWARE_TOKEN_MFA: {error_code} - {error_message}")
            return {'success': False, 'error_code': error_code, 'error_message': error_message}

    def associate_software_token(self, access_token=None, session=None):
        """
        Associate a software token (TOTP) with the user account.
        Can use either an AccessToken (after login) or a Session (during MFA setup).
        """
        try:
            params = {}
            if access_token:
                params['AccessToken'] = access_token
            elif session:
                params['Session'] = session
            else:
                raise ValueError("Must provide either access_token or session")

            response = self.cognito_client.associate_software_token(**params)

            secret_code = response['SecretCode']
            session_token = response.get('Session', None)
            return {
                'success': True,
                'secret_code': secret_code,
                'session_token': session_token,
                'qr_code_data': f'otpauth://totp/YourApp?secret={secret_code}&issuer=YourApp'
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to associate software token: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def verify_software_token(self, user_code, access_token=None, session=None):
        """
        Verify the software token (TOTP) using either AccessToken or Session.
        """
        try:
            params = {'UserCode': user_code}
            if access_token:
                params['AccessToken'] = access_token
            elif session:
                params['Session'] = session
            else:
                raise ValueError("Must provide either access_token or session")

            response = self.cognito_client.verify_software_token(**params)
            return {
                'success': True,
                'status': response['Status']
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to verify software token: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def add_user_to_group(self, username, group_name):
        """Add a user to a group"""
        try:
            self.cognito_client.admin_add_user_to_group(
                UserPoolId=self.user_pool_id,
                Username=username,
                GroupName=group_name
            )
            
            logger.info(f"User {username} added to group {group_name}")
            return {'success': True}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to add user to group: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def remove_user_from_group(self, username, group_name):
        """Remove a user from a group"""
        try:
            self.cognito_client.admin_remove_user_from_group(
                UserPoolId=self.user_pool_id,
                Username=username,
                GroupName=group_name
            )
            
            logger.info(f"User {username} removed from group {group_name}")
            return {'success': True}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to remove user from group: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def get_user_groups(self, username):
        """Get all groups that a user belongs to"""
        try:
            response = self.cognito_client.admin_list_groups_for_user(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            
            groups = [group['GroupName'] for group in response['Groups']]
            logger.info(f"Retrieved groups for user {username}: {groups}")
            
            return {
                'success': True,
                'groups': groups,
                'group_details': response['Groups']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to get user groups: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def list_all_groups(self):
        """List all groups in the user pool"""
        try:
            response = self.cognito_client.list_groups(
                UserPoolId=self.user_pool_id
            )
            
            logger.info(f"Retrieved {len(response['Groups'])} groups")
            return {
                'success': True,
                'groups': response['Groups']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to list groups: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }

    def verify_token(self, token):
        """Verify JWT token and return decoded claims with group information"""
        try:
            # Get the JWKS
            jwks = self._get_jwks()
            
            # Get the header from the token
            headers = jwt.get_unverified_header(token)
            kid = headers['kid']
            
            # Find the key in the JWKS
            key = None
            for jwk_key in jwks['keys']:
                if jwk_key['kid'] == kid:
                    key = jwk_key
                    break
            
            if not key:
                raise Exception("Unable to find appropriate key")
            
            # Verify the token
            claims = jwt.decode(
                token,
                key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=f'https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}'
            )
            
            # Extract group information from token claims
            groups = claims.get('cognito:groups', [])
            
            logger.info(f"Token verified for user: {claims.get('cognito:username', claims.get('username'))}, groups: {groups}")
            return claims
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise

    def get_user_info(self, access_token):
        """Get user information using access token"""
        try:
            response = self.cognito_client.get_user(AccessToken=access_token)
            
            user_attributes = {}
            for attr in response['UserAttributes']:
                user_attributes[attr['Name']] = attr['Value']
            
            # Get user's groups
            username = response['Username']
            groups_result = self.get_user_groups(username)
            
            return {
                'username': username,
                'attributes': user_attributes,
                'groups': groups_result.get('groups', []) if groups_result.get('success') else [],
                'mfa_enabled': user_attributes.get('phone_number_verified') == 'true' or 
                              'software_token_mfa_enabled' in user_attributes
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to get user info: {error_code} - {error_message}")
            raise

    def admin_create_user(self, username, email, temporary_password, user_group='Users'):
        """Admin create user (for testing or admin purposes)"""
        try:
            response = self.cognito_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=username,
                TemporaryPassword=temporary_password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'email_verified', 'Value': 'true'}
                ],
                MessageAction='SUPPRESS'  # Don't send welcome email
            )
            
            # Add user to group
            if user_group:
                self.add_user_to_group(username, user_group)
            
            logger.info(f"Admin created user {username} in group {user_group}")
            return {'success': True, 'user': response['User'], 'group': user_group}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Admin create user failed: {error_code} - {error_message}")
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_message
            }