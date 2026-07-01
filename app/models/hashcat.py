from app.extensions import db
from datetime import datetime

class CrackJob(db.Model):
    __tablename__ = 'crack_jobs'
    id = db.Column(db.Integer, primary_key=True)
    capture_id = db.Column(db.Integer, db.ForeignKey('wireless_captures.id'), nullable=True)
    hash_file_path = db.Column(db.String(500))
    wordlist_path = db.Column(db.String(500))
    hash_mode = db.Column(db.Integer, default=22000)
    status = db.Column(db.String(20), default='pending')
    progress = db.Column(db.String(50))
    cracked_count = db.Column(db.Integer, default=0)
    total_count = db.Column(db.Integer, default=0)
    result_path = db.Column(db.String(500))
    command_line = db.Column(db.Text)
    raw_output = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "capture_id": self.capture_id,
            "hash_file_path": self.hash_file_path,
            "wordlist_path": self.wordlist_path,
            "hash_mode": self.hash_mode,
            "status": self.status,
            "progress": self.progress,
            "cracked_count": self.cracked_count,
            "total_count": self.total_count,
            "result_path": self.result_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }
