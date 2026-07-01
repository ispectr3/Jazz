from app.extensions import db
from datetime import datetime

class WirelessScan(db.Model):
    __tablename__ = 'wireless_scans'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')
    target_bssid = db.Column(db.String(20))
    target_essid = db.Column(db.String(255))
    interface = db.Column(db.String(50), default='wlan0')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    error_log = db.Column(db.Text)
    networks = db.relationship('WirelessNetwork', backref='scan', lazy=True, cascade='all,delete-orphan')
    captures = db.relationship('WirelessCapture', backref='scan', lazy=True, cascade='all,delete-orphan')

class WirelessNetwork(db.Model):
    __tablename__ = 'wireless_networks'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('wireless_scans.id'), nullable=False)
    bssid = db.Column(db.String(20), nullable=False)
    essid = db.Column(db.String(255))
    channel = db.Column(db.Integer)
    signal = db.Column(db.Integer)
    encryption = db.Column(db.String(50))
    is_wps = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class WirelessCapture(db.Model):
    __tablename__ = 'wireless_captures'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('wireless_scans.id'), nullable=False)
    network_id = db.Column(db.Integer, db.ForeignKey('wireless_networks.id'), nullable=True)
    capture_type = db.Column(db.String(20))
    status = db.Column(db.String(20), default='capturing')
    hash_file_path = db.Column(db.String(500))
    hash_format = db.Column(db.String(50))
    raw_output = db.Column(db.Text)
    pcap_path = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
