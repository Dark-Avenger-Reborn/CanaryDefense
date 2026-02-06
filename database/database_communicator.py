"""
Database Layout

{
    "user_id": {
        "honeypots": {
            "honeypot_id": {
                "name": "Honeypot Name",
                "last_active": "Timestamp",
                "created_at": "Timestamp",
                "active_protocols": ["protocol1", "protocol2"],
                "is_active": true,
                "logs": [
                    {
                        "timestamp": "Timestamp",
                        "source_ip": "IP Address",
                        "destination_ip": "IP Address",
                        "protocol": "Protocol Type",
                        "log": "Log Details"
                    }
                ]
            }
        },
        "alerts": {
            "emails": ["email@example.com", "anotheremail@example.com"],
            "preferences": {
                "alert_on_honeypot_down": true,
                "alert_on_suspicious_activity": true
            }
        }
    }
}
"""

import json
import os
from pathlib import Path
from datetime import datetime


class DatabaseCommunicator:
    def __init__(self, db_file="database/db.json"):
        """
        Initialize JSON file database.
        
        Args:
            db_file (str): Path to the JSON database file
        """
        self.db_file = db_file
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """Create database file if it doesn't exist."""
        if not os.path.exists(self.db_file):
            Path(self.db_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_file, 'w') as f:
                json.dump({}, f, indent=2)
    
    def _load_db(self):
        """Load database from JSON file."""
        try:
            with open(self.db_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_db(self, data):
        """Save database to JSON file."""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving database: {e}")
            return False
    
    def create_user_entry(self, uid, email):
        """
        Create a new user entry in the database with the Firebase UID.
        
        Args:
            uid (str): Firebase UID
            email (str): User email
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid in db:
                return {"success": False, "error": "User already exists"}
            
            user_data = {
                "email": email,
                "honeypots": {},
                "alerts": {
                    "emails": [email],
                    "preferences": {
                        "alert_on_honeypot_down": True,
                        "alert_on_suspicious_activity": True
                    }
                }
            }
            
            db[uid] = user_data
            self._save_db(db)
            return {"success": True, "message": "User entry created in database"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def delete_user_entry(self, uid):
        """
        Delete a user entry from the database.
        
        Args:
            uid (str): Firebase UID
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            del db[uid]
            self._save_db(db)
            return {"success": True, "message": "User entry deleted from database"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_user_entry(self, uid):
        """
        Get user data from the database.
        
        Args:
            uid (str): Firebase UID
            
        Returns:
            dict: User data if found, error otherwise
        """
        try:
            db = self._load_db()
            
            if uid in db:
                return {"success": True, "data": db[uid]}
            return {"success": False, "error": "User not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_user_alerts(self, uid, emails, preferences):
        """
        Update user alert preferences and emails.
        
        Args:
            uid (str): Firebase UID
            emails (list): Alert email addresses
            preferences (dict): Alert preferences
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            alert_data = {
                "emails": emails,
                "preferences": preferences
            }
            db[uid]["alerts"] = alert_data
            self._save_db(db)
            return {"success": True, "message": "Alerts updated"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_honeypot(self, uid, name, honeypot_id=None, protocols=None, extra_data=None):
        """
        Create a new honeypot for a user.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Unique honeypot identifier
            name (str): Honeypot name
            protocols (list): List of protocols to enable
            extra_data (dict): Additional honeypot fields (optional)
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}

            user_honeypot_count = len(db[uid]["honeypots"])
            honeypot_id = honeypot_id or f"hp_{user_honeypot_count + 1:03d}"

            if honeypot_id in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot ID already exists"}
            
            from datetime import datetime
            honeypot_data = {
                "name": name,
                "created_at": datetime.now().isoformat(),
                "last_active": datetime.now().isoformat(),
                "active_protocols": protocols or [],
                "is_active": False,
                "logs": []
            }

            if extra_data:
                honeypot_data.update(extra_data)
            
            db[uid]["honeypots"][honeypot_id] = honeypot_data
            self._save_db(db)
            return {"success": True, "message": "Honeypot created successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def delete_honeypot(self, uid, honeypot_id):
        """
        Delete a honeypot.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            if honeypot_id not in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot not found"}
            
            del db[uid]["honeypots"][honeypot_id]
            self._save_db(db)
            return {"success": True, "message": "Honeypot deleted successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def list_honeypots(self, uid):
        """
        List all honeypots for a user.
        
        Args:
            uid (str): Firebase UID
            
        Returns:
            dict: List of honeypots with their data
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            return {"success": True, "honeypots": db[uid]["honeypots"]}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_honeypot(self, uid, honeypot_id):
        """
        Get a specific honeypot's data.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            
        Returns:
            dict: Honeypot data
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            if honeypot_id not in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot not found"}
            
            return {"success": True, "honeypot": db[uid]["honeypots"][honeypot_id]}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_honeypot(self, uid, honeypot_id, name=None, protocols=None, is_active=None, last_active=None):
        """
        Update honeypot configuration.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            name (str): New name (optional)
            protocols (list): New list of protocols (optional)
            is_active (bool): Active status (optional)
            last_active (str): Last active timestamp (optional)
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            if honeypot_id not in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot not found"}
            
            # Check if attempting to change protocols on an offline honeypot
            # Allow if we're also setting is_active=True in this same call (honeypot coming online)
            if protocols is not None:
                current_honeypot = db[uid]["honeypots"][honeypot_id]
                if not current_honeypot["is_active"] and not is_active:
                    return {"success": False, "error": "Cannot adjust active protocols while honeypot is offline"}
            
            if name is not None:
                db[uid]["honeypots"][honeypot_id]["name"] = name
            if protocols is not None:
                db[uid]["honeypots"][honeypot_id]["active_protocols"] = protocols
            if is_active is not None:
                db[uid]["honeypots"][honeypot_id]["is_active"] = is_active
            if last_active is not None:
                db[uid]["honeypots"][honeypot_id]["last_active"] = last_active
            
            self._save_db(db)
            return {"success": True, "message": "Honeypot updated successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def add_log(self, uid, honeypot_id, log_entry):
        """
        Add a log entry to a honeypot.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            log_entry (dict): Log entry data
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            if honeypot_id not in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot not found"}
            
            db[uid]["honeypots"][honeypot_id]["logs"].append(log_entry)
            
            from datetime import datetime
            db[uid]["honeypots"][honeypot_id]["last_active"] = datetime.now().isoformat()
            
            self._save_db(db)
            return {"success": True, "message": "Log added successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_logs(self, uid, honeypot_id):
        """
        Get all logs for a honeypot.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            
        Returns:
            dict: List of logs
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            if honeypot_id not in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot not found"}
            
            return {"success": True, "logs": db[uid]["honeypots"][honeypot_id]["logs"]}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def clear_logs(self, uid, honeypot_id):
        """
        Clear all logs for a honeypot.
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            
        Returns:
            dict: Success status
        """
        try:
            db = self._load_db()
            
            if uid not in db:
                return {"success": False, "error": "User not found"}
            
            if honeypot_id not in db[uid]["honeypots"]:
                return {"success": False, "error": "Honeypot not found"}
            
            db[uid]["honeypots"][honeypot_id]["logs"] = []
            self._save_db(db)
            return {"success": True, "message": "Logs cleared successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def turn_off_honeypot(self, uid, honeypot_id):
        """
        Turn off a honeypot (set is_active to False).
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            
        Returns:
            dict: Success status
        """
        return self.update_honeypot(uid, honeypot_id, is_active=False)

    def turn_on_honeypot(self, uid, honeypot_id):
        """
        Turn on a honeypot (set is_active to True).
        
        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            
        Returns:
            dict: Success status
        """
        self.update_honeypot(uid, honeypot_id, last_active=datetime.now().isoformat())
        return self.update_honeypot(uid, honeypot_id, is_active=True)

    def find_honeypot_owner(self, honeypot_id):
        """
        Find which user owns a given honeypot_id.
        
        Args:
            honeypot_id (str): Honeypot identifier
            
        Returns:
            str: UID of the owner, or None if not found
        """
        try:
            db = self._load_db()
            
            for uid, user_data in db.items():
                if honeypot_id in user_data.get("honeypots", {}):
                    return uid
            
            return None
        except Exception as e:
            return None