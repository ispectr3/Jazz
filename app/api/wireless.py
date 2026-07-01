from flask import Blueprint, request, jsonify, send_file
from app.models.wireless import WirelessScan, WirelessNetwork, WirelessCapture
from app.models.base import Project
from app.extensions import db
from app.tasks.wireless_tasks import run_wifite2_scan, run_hcxdumptool_capture, run_hcxtools_convert

wireless_bp = Blueprint('wireless', __name__)

@wireless_bp.route('/wireless/scan', methods=['POST'])
def start_scan():
    data = request.get_json() or {}
    interface = data.get('interface', 'wlan0')
    project_id = data.get('project_id')

    scan = WirelessScan(status='pending', interface=interface, project_id=project_id)
    db.session.add(scan)
    db.session.commit()

    task = run_wifite2_scan.apply(args=[interface, scan.id])

    return jsonify({
        "status": "scan_started",
        "scan_id": scan.id,
        "task_id": task.id,
        "interface": interface
    }), 201

@wireless_bp.route('/wireless/scans', methods=['GET'])
def list_scans():
    scans = WirelessScan.query.order_by(WirelessScan.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": s.id,
        "interface": s.interface,
        "status": s.status,
        "target_bssid": s.target_bssid,
        "target_essid": s.target_essid,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None
    } for s in scans]), 200

@wireless_bp.route('/wireless/networks/<int:scan_id>', methods=['GET'])
def list_networks(scan_id):
    networks = WirelessNetwork.query.filter_by(scan_id=scan_id).all()
    return jsonify([{
        "id": n.id,
        "bssid": n.bssid,
        "essid": n.essid,
        "channel": n.channel,
        "signal": n.signal,
        "encryption": n.encryption,
        "is_wps": n.is_wps
    } for n in networks]), 200

@wireless_bp.route('/wireless/capture', methods=['POST'])
def start_capture():
    data = request.get_json() or {}
    interface = data.get('interface', 'wlan0')
    bssid = data.get('bssid')
    channel = data.get('channel')
    scan_id = data.get('scan_id')
    network_id = data.get('network_id')

    if not bssid:
        return jsonify({"error": "bssid is required"}), 400

    task = run_hcxdumptool_capture.apply(args=[interface, bssid, channel, scan_id, network_id])

    return jsonify({
        "status": "capture_started",
        "task_id": task.id,
        "target_bssid": bssid
    }), 201

@wireless_bp.route('/wireless/captures', methods=['GET'])
def list_captures():
    captures = WirelessCapture.query.order_by(WirelessCapture.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": c.id,
        "scan_id": c.scan_id,
        "network_id": c.network_id,
        "capture_type": c.capture_type,
        "status": c.status,
        "hash_format": c.hash_format,
        "created_at": c.created_at.isoformat() if c.created_at else None
    } for c in captures]), 200

@wireless_bp.route('/wireless/convert/<int:capture_id>', methods=['POST'])
def convert_capture(capture_id):
    task = run_hcxtools_convert.apply(args=[capture_id])
    return jsonify({
        "status": "conversion_started",
        "task_id": task.id,
        "capture_id": capture_id
    }), 202

@wireless_bp.route('/wireless/hash/<int:capture_id>', methods=['GET'])
def download_hash(capture_id):
    capture = WirelessCapture.query.get(capture_id)
    if not capture or not capture.hash_file_path:
        return jsonify({"error": "Hash not found or not yet converted"}), 404

    try:
        return send_file(capture.hash_file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "Hash file not found on disk"}), 404
