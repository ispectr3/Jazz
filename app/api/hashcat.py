from flask import Blueprint, request, jsonify, send_file
from app.models.hashcat import CrackJob
from app.models.wireless import WirelessCapture
from app.extensions import db
from app.tasks.hashcat_tasks import run_hashcat_crack
import os

hashcat_bp = Blueprint('hashcat', __name__)

@hashcat_bp.route('/hashcat/crack', methods=['POST'])
def start_crack():
    data = request.get_json() or {}
    capture_id = data.get('capture_id')
    wordlist_path = data.get('wordlist', os.path.expanduser('~/wordlists/rockyou.txt'))
    hash_mode = data.get('hash_mode', 22000)

    if capture_id:
        capture = WirelessCapture.query.get(capture_id)
        if not capture:
            return jsonify({"error": "Capture not found"}), 404
        if not capture.hash_file_path or not os.path.exists(capture.hash_file_path):
            return jsonify({"error": "Hash file not found. Convert capture first."}), 400
        hash_path = capture.hash_file_path
    else:
        hash_path = data.get('hash_file')
        if not hash_path:
            return jsonify({"error": "Provide capture_id or hash_file"}), 400

    if not os.path.exists(wordlist_path):
        return jsonify({"error": f"Wordlist not found: {wordlist_path}"}), 400

    job = CrackJob(
        capture_id=capture_id,
        hash_file_path=hash_path,
        wordlist_path=wordlist_path,
        hash_mode=hash_mode,
        status='pending'
    )
    db.session.add(job)
    db.session.commit()

    task = run_hashcat_crack.apply(args=[job.id])

    return jsonify({
        "status": "crack_started",
        "job_id": job.id,
        "task_id": task.id,
        "hash_mode": hash_mode,
        "wordlist": wordlist_path,
        "hash_file": hash_path
    }), 201

@hashcat_bp.route('/hashcat/jobs', methods=['GET'])
def list_jobs():
    jobs = CrackJob.query.order_by(CrackJob.created_at.desc()).limit(20).all()
    return jsonify([j.to_dict() for j in jobs]), 200

@hashcat_bp.route('/hashcat/job/<int:job_id>', methods=['GET'])
def get_job(job_id):
    job = CrackJob.query.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict()), 200

@hashcat_bp.route('/hashcat/result/<int:job_id>', methods=['GET'])
def download_result(job_id):
    job = CrackJob.query.get(job_id)
    if not job or not job.result_path:
        return jsonify({"error": "No result file"}), 404
    try:
        return send_file(job.result_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "Result file not found"}), 404

@hashcat_bp.route('/hashcat/potfile', methods=['GET'])
def read_potfile():
    potfile = os.path.expanduser('~/.local/share/hashcat/hashcat.potfile')
    if not os.path.exists(potfile):
        potfile = os.path.expanduser('~/.hashcat/hashcat.potfile')
    if not os.path.exists(potfile):
        return jsonify({"entries": []}), 200
    try:
        with open(potfile) as f:
            lines = [l.strip() for l in f if l.strip()]
        return jsonify({"entries": lines, "count": len(lines)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
