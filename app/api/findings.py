from flask import Blueprint, jsonify, request
from app.models.base import Finding, Project
from app.extensions import db
from sqlalchemy import func, desc

SEVERITY_MAP = {
    "critica": "Critica",
    "alta": "Alta",
    "media": "Media",
    "baixa": "Baixa",
    "info": "Info",
}

findings_bp = Blueprint('findings', __name__)

def _build_severity_filter(severity_param: str):
    filters = []
    for token in severity_param.lower().split(","):
        token = token.strip()
        if token in SEVERITY_MAP:
            label = SEVERITY_MAP[token]
            filters.append(Finding.severity.ilike(f"%{label}%"))
            filters.append(Finding.severity.ilike(f"%{label.lower()}%"))
    return filters

@findings_bp.route('/stats', methods=['GET'])
def get_stats():
    severity_filter = request.args.get("severity")
    base_q = Finding.query
    if severity_filter:
        sf = _build_severity_filter(severity_filter)
        if sf:
            base_q = base_q.filter(db.or_(*sf))
    total = base_q.count()

    severity_counts = db.session.query(
        Finding.severity, func.count(Finding.id)
    )
    if severity_filter:
        sf = _build_severity_filter(severity_filter)
        if sf:
            severity_counts = severity_counts.filter(db.or_(*sf))
    severity_counts = severity_counts.group_by(Finding.severity).all()

    stats = {
        "total": total,
        "criticas": 0,
        "altas": 0,
        "medias": 0,
        "baixas": 0,
        "ultimo_alvo": None
    }

    for sev, count in severity_counts:
        sev_lower = sev.lower() if sev else ""
        if "crítica" in sev_lower or "critica" in sev_lower:
            stats["criticas"] += count
        elif "alta" in sev_lower or "high" in sev_lower:
            stats["altas"] += count
        elif "média" in sev_lower or "media" in sev_lower or "medium" in sev_lower:
            stats["medias"] += count
        elif "baixa" in sev_lower or "low" in sev_lower:
            stats["baixas"] += count

    last_q = Finding.query.order_by(desc(Finding.created_at))
    if severity_filter:
        sf = _build_severity_filter(severity_filter)
        if sf:
            last_q = last_q.filter(db.or_(*sf))
    last = last_q.first()
    if last and last.raw_data:
        stats["ultimo_alvo"] = str(last.raw_data)[:80]

    return jsonify(stats), 200

@findings_bp.route('/', methods=['GET'])
def get_findings():
    severity_filter = request.args.get("severity")

    base_q = Finding.query.order_by(Finding.created_at.desc())
    if severity_filter:
        sf = _build_severity_filter(severity_filter)
        if sf:
            base_q = base_q.filter(db.or_(*sf))
    findings = base_q.limit(50).all()

    result = []
    for f in findings:
        desc_preview = ""
        if f.description:
            report_idx = f.description.find("--- JAIZZ NOIR")
            if report_idx >= 0:
                desc_preview = f.description[:report_idx].strip()
            else:
                desc_preview = f.description[:200].strip()

        plugin_short = f.plugin_source.replace("OSINT Scanner", "").replace("Framework", "").replace("Suite", "").strip()
        if len(plugin_short) > 20:
            plugin_short = plugin_short[:18] + ".."

        raw = f.raw_data or {}
        url = ""
        if isinstance(raw, dict):
            url = raw.get("url", raw.get("hostname", raw.get("ip", "")))

        result.append({
            "id": f.id,
            "project_id": f.project_id,
            "plugin_source": plugin_short,
            "title": f.title,
            "severity": f.severity,
            "description": desc_preview,
            "full_report": f.description or "",
            "url": str(url)[:80],
            "created_at": f.created_at.isoformat()
        })

    return jsonify(result), 200

@findings_bp.route('/grouped', methods=['GET'])
def get_findings_grouped():
    severity_filter = request.args.get("severity")
    project_id = request.args.get("project_id", type=int)

    base_q = Finding.query.order_by(Finding.created_at.desc())
    if project_id:
        base_q = base_q.filter_by(project_id=project_id)
    if severity_filter:
        sf = _build_severity_filter(severity_filter)
        if sf:
            base_q = base_q.filter(db.or_(*sf))
    findings = base_q.limit(100).all()

    groups = {}
    for f in findings:
        src = f.plugin_source or "Unknown"
        if src not in groups:
            groups[src] = {"criticas": 0, "altas": 0, "medias": 0, "baixas": 0, "info": 0, "findings": []}

        sev_lower = (f.severity or "").lower()
        if "critica" in sev_lower or "crit" in sev_lower:
            groups[src]["criticas"] += 1
        elif "alta" in sev_lower or "high" in sev_lower:
            groups[src]["altas"] += 1
        elif "media" in sev_lower or "medium" in sev_lower:
            groups[src]["medias"] += 1
        elif "baixa" in sev_lower or "low" in sev_lower:
            groups[src]["baixas"] += 1
        else:
            groups[src]["info"] += 1

        desc_preview = ""
        if f.description:
            report_idx = f.description.find("--- JAIZZ NOIR")
            if report_idx >= 0:
                desc_preview = f.description[:report_idx].strip()
            else:
                desc_preview = f.description[:200].strip()

        groups[src]["findings"].append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity or "Info",
            "description": desc_preview,
            "full_report": f.description or "",
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    result = []
    for src, data in sorted(groups.items()):
        data["plugin_source"] = src
        data["total"] = data["criticas"] + data["altas"] + data["medias"] + data["baixas"] + data["info"]
        result.append(data)

    return jsonify(result), 200

@findings_bp.route('/<int:finding_id>', methods=['GET'])
def get_finding(finding_id):
    f = Finding.query.get(finding_id)
    if not f:
        return jsonify({"error": "Finding not found"}), 404
    raw = f.raw_data or {}
    return jsonify({
        "id": f.id,
        "project_id": f.project_id,
        "plugin_source": f.plugin_source,
        "title": f.title,
        "severity": f.severity,
        "description": f.description or "",
        "raw_data": raw,
        "created_at": f.created_at.isoformat() if f.created_at else None
    }), 200
