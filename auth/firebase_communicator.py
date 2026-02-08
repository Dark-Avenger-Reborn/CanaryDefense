import pyrebase
from dotenv import load_dotenv
import os
import json
load_dotenv('../.env')

class firebase_auth:
    def _format_error(self, error):
        """Extract readable error messages from Firebase exceptions."""
        raw_message = str(error)
        message = None

        # Try to pull JSON payload out of the exception args or message
        candidates = list(error.args) if hasattr(error, "args") else []
        candidates.append(raw_message)

        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            if "{" not in candidate:
                continue
            json_part = candidate[candidate.find("{"):]
            try:
                payload = json.loads(json_part)
                message = payload.get("error", {}).get("message")
                if message:
                    break
            except Exception:
                continue

        if not message:
            message = raw_message

        # If message has a colon, prefer the portion after it for readability
        if ":" in message:
            parts = message.split(":", 1)
            if parts[1].strip():
                message = parts[1].strip()

        normalized = message.replace("*", "").strip()

        friendly_map = {
            "INVALID_LOGIN_CREDENTIALS": "Invalid email or password.",
            "INVALID_PASSWORD": "Invalid email or password.",
            "EMAIL_NOT_FOUND": "No account found for that email.",
            "EMAIL_EXISTS": "An account with that email already exists.",
            "OPERATION_NOT_ALLOWED": "Operation not allowed. Please verify the email address first.",
            "USER_DISABLED": "This account has been disabled.",
            "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts. Please try again later.",
        }

        key = normalized.split()[0] if normalized else ""
        if normalized in friendly_map:
            return friendly_map[normalized]
        if key in friendly_map:
            return friendly_map[key]

        # Default fallback: prettify underscores
        return normalized.replace("_", " ").capitalize()

    def __init__(self, config=None):
        """
        Initialize Firebase authentication.
        
        Args:
            config (dict): Firebase configuration dictionary with keys:
                - apiKey
                - authDomain
                - databaseURL
                - projectId
                - storageBucket
                - messagingSenderId
                - appId
        """
        if config is None:
            # Default config - update with your Firebase project details
            config = {
                "apiKey": os.getenv("API_KEY"),
                "authDomain": os.getenv("AUTH_DOMAIN"),
                "databaseURL": os.getenv("DATABASE_URL"),
                "projectId": os.getenv("PROJECT_ID"),
                "storageBucket": os.getenv("STORAGE_BUCKET"),
                "messagingSenderId": os.getenv("MESSAGING_SENDER_ID"),
                "appId": os.getenv("APP_ID")
            }
        
        self.firebase = pyrebase.initialize_app(config)
        self.auth = self.firebase.auth()
    
    def create_user(self, email, password):
        """
        Create a new user account.
        
        Args:
            email (str): User email
            password (str): User password
            
        Returns:
            dict: User data including uid if successful, error message if failed
        """
        try:
            user = self.auth.create_user_with_email_and_password(email, password)
            return {
                "success": True,
                "uid": user["localId"],
                "email": user["email"],
                "id_token": user["idToken"]
            }
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def sign_in(self, email, password):
        """
        Sign in a user.
        
        Args:
            email (str): User email
            password (str): User password
            
        Returns:
            dict: User data including uid and id_token if successful
        """
        try:
            user = self.auth.sign_in_with_email_and_password(email, password)
            return {
                "success": True,
                "uid": user["localId"],
                "email": user["email"],
                "id_token": user["idToken"],
                "refresh_token": user["refreshToken"]
            }
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def delete_user(self, id_token):
        """
        Delete the currently authenticated user account.
        
        Args:
            id_token (str): ID token of the user to delete
            
        Returns:
            dict: Success status
        """
        try:
            self.auth.delete_user_account(id_token)
            return {"success": True, "message": "User account deleted successfully"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def get_user_info(self, id_token):
        """
        Get information about the currently authenticated user.
        
        Args:
            id_token (str): ID token of the user
            
        Returns:
            dict: User information if successful
        """
        try:
            user_info = self.auth.get_account_info(id_token)
            users = user_info["users"]
            if users:
                user = users[0]
                return {
                    "success": True,
                    "uid": user.get("localId"),
                    "email": user.get("email"),
                    "email_verified": user.get("emailVerified"),
                    "creation_time": user.get("createdAt"),
                    "last_login": user.get("lastLoginAt"),
                    "display_name": user.get("displayName"),
                    "phone_number": user.get("phoneNumber"),
                    "photo_url": user.get("photoUrl")
                }
            return {"success": False, "error": "User not found"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def send_email_verification(self, id_token):
        """
        Send email verification link to the user.
        
        Args:
            id_token (str): ID token of the user
            
        Returns:
            dict: Success status
        """
        try:
            self.auth.send_email_verification(id_token)
            return {"success": True, "message": "Verification email sent"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def reset_password(self, email):
        """
        Send password reset email.
        
        Args:
            email (str): Email of the user
            
        Returns:
            dict: Success status
        """
        try:
            self.auth.send_password_reset_email(email)
            return {"success": True, "message": "Password reset email sent"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def change_email(self, id_token, new_email):
        """
        Change user email address.
        
        Args:
            id_token (str): ID token of the user
            new_email (str): New email address
            
        Returns:
            dict: Success status
        """
        try:
            self.auth.change_email(id_token, new_email)
            return {"success": True, "message": "Email changed successfully"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def change_password(self, id_token, new_password):
        """
        Change user password.
        
        Args:
            id_token (str): ID token of the user
            new_password (str): New password
            
        Returns:
            dict: Success status
        """
        try:
            self.auth.change_password(id_token, new_password)
            return {"success": True, "message": "Password changed successfully"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def change_username(self, id_token, new_username):
        """
        Change user display name (username).
        
        Args:
            id_token (str): ID token of the user
            new_username (str): New username/display name
            
        Returns:
            dict: Success status
        """
        try:
            self.auth.update_profile(id_token, display_name=new_username)
            return {"success": True, "message": "Username changed successfully"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def refresh_token(self, refresh_token):
        """
        Refresh the user's ID token.
        
        Args:
            refresh_token (str): User's refresh token
            
        Returns:
            dict: New ID token if successful
        """
        try:
            user = self.auth.refresh(refresh_token)
            return {
                "success": True,
                "id_token": user["idToken"],
                "refresh_token": user["refreshToken"]
            }
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}
    
    def update_profile(self, id_token, display_name=None, photo_url=None):
        """
        Update user profile information.
        
        Args:
            id_token (str): ID token of the user
            display_name (str, optional): New display name
            photo_url (str, optional): New photo URL
            
        Returns:
            dict: Success status
        """
        try:
            kwargs = {}
            if display_name:
                kwargs["display_name"] = display_name
            if photo_url:
                kwargs["photo_url"] = photo_url
            
            self.auth.update_user_profile(id_token, **kwargs)
            return {"success": True, "message": "Profile updated successfully"}
        except Exception as e:
            return {"success": False, "error": self._format_error(e)}