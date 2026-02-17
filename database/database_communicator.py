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
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path


class DatabaseCommunicator:
    def __init__(self, db_file="database/db.sqlite", json_db_file="database/db.json"):
        """
        Initialize SQLite database.

        Args:
            db_file (str): Path to the SQLite database file
            json_db_file (str): Path to legacy JSON database file for migration
        """
        self.db_file = db_file
        self.json_db_file = json_db_file
        self._ensure_db_exists()
        self._migrate_from_json_if_needed()

    def _connect(self):
        conn = sqlite3.connect(self.db_file, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _ensure_db_exists(self):
        """Create database file and schema if it doesn't exist."""
        Path(self.db_file).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users (uid TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )

    def _user_count(self):
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
            return int(row["count"]) if row else 0

    def _migrate_from_json_if_needed(self):
        if not os.path.exists(self.json_db_file):
            return
        if self._user_count() > 0:
            return

        try:
            with open(self.json_db_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        if not isinstance(data, dict) or not data:
            return

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for uid, user_data in data.items():
                    if not isinstance(user_data, dict):
                        continue
                    self._ensure_user_stats(user_data)
                    conn.execute(
                        "INSERT OR REPLACE INTO users(uid, data) VALUES(?, ?)",
                        (uid, json.dumps(user_data)),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    @contextmanager
    def _transaction(self):
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _load_user_data(self, conn, uid):
        row = conn.execute("SELECT data FROM users WHERE uid = ?", (uid,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["data"])
        except json.JSONDecodeError:
            return None

    def _save_user_data(self, conn, uid, user_data):
        conn.execute(
            "INSERT OR REPLACE INTO users(uid, data) VALUES(?, ?)",
            (uid, json.dumps(user_data)),
        )

    def _ensure_user_stats(self, user_data):
        """Ensure user stats exist for cumulative counters."""
        stats = user_data.get("stats")
        honeypots = user_data.get("honeypots", {})
        total_honeypots = len(honeypots)
        total_logs = sum(len(hp.get("logs", [])) for hp in honeypots.values())

        if not isinstance(stats, dict):
            user_data["stats"] = {
                "total_honeypots_created": total_honeypots,
                "total_logs_captured": total_logs
            }
            return

        stats["total_honeypots_created"] = max(
            stats.get("total_honeypots_created", 0),
            total_honeypots
        )
        stats["total_logs_captured"] = max(
            stats.get("total_logs_captured", 0),
            total_logs
        )

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
            with self._transaction() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM users WHERE uid = ?", (uid,)
                ).fetchone()
                if existing:
                    return {"success": False, "error": "User already exists"}

                user_data = {
                    "email": email,
                    "honeypots": {},
                    "stats": {
                        "total_honeypots_created": 0,
                        "total_logs_captured": 0
                    },
                    "invites": [],
                    "activity_log": [],
                    "alerts": {
                        "emails": [email],
                        "preferences": {
                            "alert_on_honeypot_down": True,
                            "alert_on_suspicious_activity": True
                        }
                    }
                }

                self._save_user_data(conn, uid, user_data)
            return {"success": True, "message": "User entry created in database"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_user_basic(self, uid):
        """
        Get basic profile info for a user.

        Returns:
            dict: user profile data
        """
        try:
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}
                return {
                    "success": True,
                    "uid": uid,
                    "email": user_data.get("email"),
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def find_uid_by_email(self, email):
        """
        Find a UID by email.

        Args:
            email (str): Email to search

        Returns:
            str: UID if found, else None
        """
        if not email:
            return None
        normalized = email.strip().lower()
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT uid, data FROM users").fetchall()
                for row in rows:
                    try:
                        user_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue
                    stored = (user_data.get("email") or "").strip().lower()
                    if stored and stored == normalized:
                        return row["uid"]
            return None
        except Exception:
            return None

    def list_accessible_honeypots(self, uid):
        """
        List honeypots owned by the user and those shared with them.

        Returns:
            dict: Mapping of honeypot_id to honeypot data
        """
        try:
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                owned = {}
                for hp_id, hp_data in user_data.get("honeypots", {}).items():
                    owned[hp_id] = {
                        **hp_data,
                        "shared": False,
                        "owner_uid": uid,
                        "access_role": "owner",
                        "can_delete": True
                    }

                shared = {}
                rows = conn.execute("SELECT uid, data FROM users").fetchall()
                for row in rows:
                    owner_uid = row["uid"]
                    if owner_uid == uid:
                        continue
                    try:
                        owner_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue
                    for hp_id, hp_data in owner_data.get("honeypots", {}).items():
                        collaborators = hp_data.get("collaborators", {})
                        if uid not in collaborators:
                            continue
                        access = collaborators.get(uid, {})
                        shared[hp_id] = {
                            **hp_data,
                            "shared": True,
                            "owner_uid": owner_uid,
                            "access_role": access.get("role", "read"),
                            "can_delete": bool(access.get("can_delete"))
                        }

                merged = dict(shared)
                merged.update(owned)
                return {"success": True, "honeypots": merged}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def resolve_honeypot_access(self, uid, honeypot_id):
        """
        Resolve access to a honeypot, returning owner and permissions.
        """
        try:
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                if honeypot_id in user_data.get("honeypots", {}):
                    return {
                        "success": True,
                        "owner_uid": uid,
                        "role": "owner",
                        "can_delete": True
                    }

                rows = conn.execute("SELECT uid, data FROM users").fetchall()
                for row in rows:
                    owner_uid = row["uid"]
                    if owner_uid == uid:
                        continue
                    try:
                        owner_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue
                    honeypot = owner_data.get("honeypots", {}).get(honeypot_id)
                    if not honeypot:
                        continue
                    collaborators = honeypot.get("collaborators", {})
                    if uid in collaborators:
                        access = collaborators.get(uid, {})
                        return {
                            "success": True,
                            "owner_uid": owner_uid,
                            "role": access.get("role", "read"),
                            "can_delete": bool(access.get("can_delete"))
                        }

                return {"success": False, "error": "Honeypot not found or access denied"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_honeypot_with_access(self, uid, honeypot_id):
        """
        Get honeypot data with access context resolved.
        """
        access = self.resolve_honeypot_access(uid, honeypot_id)
        if not access.get("success"):
            return access

        owner_uid = access.get("owner_uid")
        result = self.get_honeypot(owner_uid, honeypot_id)
        if not result.get("success"):
            return result

        return {
            "success": True,
            "honeypot": result.get("honeypot"),
            "owner_uid": owner_uid,
            "role": access.get("role"),
            "can_delete": access.get("can_delete")
        }

    def add_invite(self, owner_uid, honeypot_id, invitee_uid, role, can_delete, invited_by_uid):
        """
        Invite a user to a honeypot.
        """
        try:
            with self._transaction() as conn:
                owner_data = self._load_user_data(conn, owner_uid)
                if owner_data is None:
                    return {"success": False, "error": "Owner not found"}
                honeypot = owner_data.get("honeypots", {}).get(honeypot_id)
                if not honeypot:
                    return {"success": False, "error": "Honeypot not found"}

                collaborators = honeypot.setdefault("collaborators", {})
                if invitee_uid in collaborators:
                    return {"success": False, "error": "User already has access"}

                invitee_data = self._load_user_data(conn, invitee_uid)
                if invitee_data is None:
                    return {"success": False, "error": "Invitee not found"}

                invites = invitee_data.setdefault("invites", [])
                for invite in invites:
                    if invite.get("owner_uid") == owner_uid and invite.get("honeypot_id") == honeypot_id:
                        return {"success": False, "error": "Invite already sent"}

                invites.append({
                    "owner_uid": owner_uid,
                    "honeypot_id": honeypot_id,
                    "role": role,
                    "can_delete": bool(can_delete),
                    "invited_by": invited_by_uid,
                    "invited_at": datetime.now().isoformat()
                })

                self._save_user_data(conn, invitee_uid, invitee_data)
            return {"success": True, "message": "Invite sent"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_invites(self, uid):
        try:
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}
                return {"success": True, "invites": user_data.get("invites", [])}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def accept_invite(self, uid, owner_uid, honeypot_id):
        try:
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                invites = user_data.get("invites", [])
                invite = None
                remaining = []
                for item in invites:
                    if item.get("owner_uid") == owner_uid and item.get("honeypot_id") == honeypot_id:
                        invite = item
                    else:
                        remaining.append(item)
                if invite is None:
                    return {"success": False, "error": "Invite not found"}

                owner_data = self._load_user_data(conn, owner_uid)
                if owner_data is None:
                    return {"success": False, "error": "Owner not found"}

                honeypot = owner_data.get("honeypots", {}).get(honeypot_id)
                if not honeypot:
                    return {"success": False, "error": "Honeypot not found"}

                collaborators = honeypot.setdefault("collaborators", {})
                collaborators[uid] = {
                    "role": invite.get("role", "read"),
                    "can_delete": bool(invite.get("can_delete")),
                    "added_at": datetime.now().isoformat(),
                    "added_by": invite.get("invited_by")
                }

                user_data["invites"] = remaining
                self._save_user_data(conn, uid, user_data)
                self._save_user_data(conn, owner_uid, owner_data)
            return {"success": True, "message": "Invite accepted"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def decline_invite(self, uid, owner_uid, honeypot_id):
        try:
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                invites = user_data.get("invites", [])
                remaining = [
                    invite for invite in invites
                    if not (
                        invite.get("owner_uid") == owner_uid
                        and invite.get("honeypot_id") == honeypot_id
                    )
                ]
                user_data["invites"] = remaining
                self._save_user_data(conn, uid, user_data)
            return {"success": True, "message": "Invite declined"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def update_collaborator(self, owner_uid, honeypot_id, collaborator_uid, role, can_delete):
        try:
            with self._transaction() as conn:
                owner_data = self._load_user_data(conn, owner_uid)
                if owner_data is None:
                    return {"success": False, "error": "Owner not found"}
                honeypot = owner_data.get("honeypots", {}).get(honeypot_id)
                if not honeypot:
                    return {"success": False, "error": "Honeypot not found"}

                collaborators = honeypot.setdefault("collaborators", {})
                if collaborator_uid not in collaborators:
                    return {"success": False, "error": "Collaborator not found"}

                collaborators[collaborator_uid]["role"] = role
                collaborators[collaborator_uid]["can_delete"] = bool(can_delete)
                collaborators[collaborator_uid]["updated_at"] = datetime.now().isoformat()
                self._save_user_data(conn, owner_uid, owner_data)
            return {"success": True, "message": "Collaborator updated"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def remove_collaborator(self, owner_uid, honeypot_id, collaborator_uid):
        try:
            with self._transaction() as conn:
                owner_data = self._load_user_data(conn, owner_uid)
                if owner_data is None:
                    return {"success": False, "error": "Owner not found"}
                honeypot = owner_data.get("honeypots", {}).get(honeypot_id)
                if not honeypot:
                    return {"success": False, "error": "Honeypot not found"}

                collaborators = honeypot.get("collaborators", {})
                if collaborator_uid in collaborators:
                    del collaborators[collaborator_uid]
                self._save_user_data(conn, owner_uid, owner_data)
            return {"success": True, "message": "Collaborator removed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def record_activity(self, owner_uid, action, honeypot_id=None, actor_uid=None, actor_username=None, details=None):
        try:
            with self._transaction() as conn:
                owner_data = self._load_user_data(conn, owner_uid)
                if owner_data is None:
                    return {"success": False, "error": "Owner not found"}

                log = owner_data.setdefault("activity_log", [])
                log.append({
                    "timestamp": datetime.now().isoformat(),
                    "action": action,
                    "honeypot_id": honeypot_id,
                    "actor_uid": actor_uid,
                    "actor_username": actor_username,
                    "details": details or {}
                })
                owner_data["activity_log"] = log[-50:]
                self._save_user_data(conn, owner_uid, owner_data)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_recent_activity(self, uid, limit=10):
        try:
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                log = user_data.get("activity_log", [])
                return {"success": True, "activity": list(reversed(log))[:limit]}
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
            with self._transaction() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM users WHERE uid = ?", (uid,)
                ).fetchone()
                if not existing:
                    return {"success": False, "error": "User not found"}

                conn.execute("DELETE FROM users WHERE uid = ?", (uid,))
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
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                self._ensure_user_stats(user_data)
                self._save_user_data(conn, uid, user_data)
                return {"success": True, "data": user_data}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_user_stats(self, uid):
        """Get cumulative stats for a user."""
        try:
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                self._ensure_user_stats(user_data)
                self._save_user_data(conn, uid, user_data)
                return {"success": True, "stats": user_data["stats"]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_global_counts(self):
        """
        Get global counts across all users.

        Returns:
            dict: Total user count, honeypot count, and log count
        """
        try:
            with self._transaction() as conn:
                rows = conn.execute("SELECT uid, data FROM users").fetchall()
                total_users = len(rows)
                total_honeypots = 0
                total_logs = 0

                for row in rows:
                    try:
                        user_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue
                    self._ensure_user_stats(user_data)
                    stats = user_data.get("stats", {})
                    total_honeypots += stats.get("total_honeypots_created", 0)
                    total_logs += stats.get("total_logs_captured", 0)
                    self._save_user_data(conn, row["uid"], user_data)

                return {
                    "success": True,
                    "total_users": total_users,
                    "total_honeypots": total_honeypots,
                    "total_logs": total_logs
                }
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
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                user_data["alerts"] = {
                    "emails": emails,
                    "preferences": preferences
                }
                self._save_user_data(conn, uid, user_data)
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
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                self._ensure_user_stats(user_data)

                user_honeypot_count = len(user_data.get("honeypots", {}))
                honeypot_id = honeypot_id or f"hp_{user_honeypot_count + 1:03d}"

                honeypots = user_data.setdefault("honeypots", {})
                if honeypot_id in honeypots:
                    return {"success": False, "error": "Honeypot ID already exists"}

                honeypot_data = {
                    "name": name,
                    "created_at": datetime.now().isoformat(),
                    "last_active": datetime.now().isoformat(),
                    "active_protocols": protocols or [],
                    "is_active": False,
                    "logs": [],
                    "log_clear_at": None,
                    "collaborators": {}
                }

                if extra_data:
                    honeypot_data.update(extra_data)

                honeypots[honeypot_id] = honeypot_data
                user_data["stats"]["total_honeypots_created"] += 1
                self._save_user_data(conn, uid, user_data)
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
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                self._ensure_user_stats(user_data)
                honeypots = user_data.get("honeypots", {})
                if honeypot_id not in honeypots:
                    return {"success": False, "error": "Honeypot not found"}

                del honeypots[honeypot_id]
                self._save_user_data(conn, uid, user_data)
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
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                return {"success": True, "honeypots": user_data.get("honeypots", {})}
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
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                honeypots = user_data.get("honeypots", {})
                if honeypot_id not in honeypots:
                    return {"success": False, "error": "Honeypot not found"}

                return {"success": True, "honeypot": honeypots[honeypot_id]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def update_honeypot(self, uid, honeypot_id, name=None, description=None, protocols=None, is_active=None, last_active=None, last_alert_email_sent_at=None):
        """
        Update honeypot configuration.

        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier
            name (str): New name (optional)
            description (str): New description (optional)
            protocols (list): New list of protocols (optional)
            is_active (bool): Active status (optional)
            last_active (str): Last active timestamp (optional)
            last_alert_email_sent_at (str): Last alert email sent timestamp (optional)

        Returns:
            dict: Success status
        """
        try:
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                honeypots = user_data.get("honeypots", {})
                if honeypot_id not in honeypots:
                    return {"success": False, "error": "Honeypot not found"}

                if protocols is not None:
                    current_honeypot = honeypots[honeypot_id]
                    if not current_honeypot.get("is_active") and not is_active:
                        return {"success": False, "error": "Cannot adjust active protocols while honeypot is offline"}

                if name is not None:
                    honeypots[honeypot_id]["name"] = name
                if description is not None:
                    honeypots[honeypot_id]["description"] = description
                if protocols is not None:
                    honeypots[honeypot_id]["active_protocols"] = protocols
                if is_active is not None:
                    honeypots[honeypot_id]["is_active"] = is_active
                if last_active is not None:
                    honeypots[honeypot_id]["last_active"] = last_active
                if last_alert_email_sent_at is not None:
                    honeypots[honeypot_id]["last_alert_email_sent_at"] = last_alert_email_sent_at

                self._save_user_data(conn, uid, user_data)
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
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                self._ensure_user_stats(user_data)
                honeypots = user_data.get("honeypots", {})
                if honeypot_id not in honeypots:
                    return {"success": False, "error": "Honeypot not found"}

                honeypot = honeypots[honeypot_id]
                if "timestamp" not in log_entry:
                    log_entry["timestamp"] = datetime.now().isoformat()

                clear_cutoff = honeypot.get("log_clear_at")
                if clear_cutoff:
                    log_time = self._parse_iso_datetime(log_entry.get("timestamp"))
                    cutoff_time = self._parse_iso_datetime(clear_cutoff)
                    if log_time and cutoff_time and log_time <= cutoff_time:
                        return {
                            "success": True,
                            "ignored": True,
                            "message": "Log ignored (before clear cutoff)"
                        }

                honeypot.setdefault("logs", []).append(log_entry)
                user_data["stats"]["total_logs_captured"] += 1
                honeypot["last_active"] = datetime.now().isoformat()

                self._save_user_data(conn, uid, user_data)
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
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                honeypots = user_data.get("honeypots", {})
                if honeypot_id not in honeypots:
                    return {"success": False, "error": "Honeypot not found"}

                return {"success": True, "logs": honeypots[honeypot_id].get("logs", [])}
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
            with self._transaction() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return {"success": False, "error": "User not found"}

                self._ensure_user_stats(user_data)
                honeypots = user_data.get("honeypots", {})
                if honeypot_id not in honeypots:
                    return {"success": False, "error": "Honeypot not found"}

                honeypots[honeypot_id]["logs"] = []
                honeypots[honeypot_id]["log_clear_at"] = datetime.now().isoformat()
                self._save_user_data(conn, uid, user_data)
            return {"success": True, "message": "Logs cleared successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _parse_iso_datetime(value):
        if not value or not isinstance(value, str):
            return None
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)
        except Exception:
            return None

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
            with self._connect() as conn:
                rows = conn.execute("SELECT uid, data FROM users").fetchall()
                for row in rows:
                    try:
                        user_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue
                    if honeypot_id in user_data.get("honeypots", {}):
                        return row["uid"]
                return None
        except Exception:
            return None

    def get_last_alert_email_time(self, uid, honeypot_id):
        """
        Get the timestamp of the last alert email sent for a honeypot.

        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier

        Returns:
            str: ISO format timestamp or None if no email has been sent
        """
        try:
            with self._connect() as conn:
                user_data = self._load_user_data(conn, uid)
                if user_data is None:
                    return None
                honeypot = user_data.get("honeypots", {}).get(honeypot_id)
                if honeypot is None:
                    return None
                return honeypot.get("last_alert_email_sent_at")
        except Exception:
            return None

    def update_last_alert_email_time(self, uid, honeypot_id):
        """
        Update the timestamp of the last alert email sent for a honeypot to now.

        Args:
            uid (str): Firebase UID
            honeypot_id (str): Honeypot identifier

        Returns:
            dict: Success status
        """
        return self.update_honeypot(
            uid,
            honeypot_id,
            last_alert_email_sent_at=datetime.now().isoformat()
        )
