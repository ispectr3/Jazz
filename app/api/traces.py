from flask import Blueprint, jsonify, request

from app.ai.tracer import get_traces, get_trace_stats
from app.ai.summarizer import get_flow_context, summarize_flow, get_qa_history

traces_bp = Blueprint("traces", __name__)


@traces_bp.route("/flows/<int:flow_id>/context", methods=["GET"])
def flow_context(flow_id):
    iteration = request.args.get("iteration", 1, type=int)
    include_summary = request.args.get("include_summary", "true").lower() == "true"
    ctx = get_flow_context(flow_id, iteration, include_summary)
    qa_list = get_qa_history(flow_id, iteration, limit=100)
    return jsonify({
        "flow_id": flow_id,
        "iteration": iteration,
        "context": ctx,
        "qa_count": len(qa_list),
        "qa_pairs": qa_list,
    })


@traces_bp.route("/flows/<int:flow_id>/summarize", methods=["POST"])
def flow_summarize(flow_id):
    data = request.get_json() or {}
    iteration = data.get("iteration", 1)
    summary = summarize_flow(flow_id, iteration)
    return jsonify({
        "flow_id": flow_id,
        "iteration": iteration,
        "summary": summary,
    })


@traces_bp.route("/traces", methods=["GET"])
def list_traces():
    target = request.args.get("target")
    phase = request.args.get("phase")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    traces = get_traces(target=target, phase=phase, limit=limit, offset=offset)
    stats = get_trace_stats(target=target)
    return jsonify({
        "traces": traces,
        "stats": stats,
        "limit": limit,
        "offset": offset,
        "total": len(traces),
    })


@traces_bp.route("/traces/<int:trace_id>", methods=["GET"])
def trace_detail(trace_id):
    traces = get_traces(limit=1, offset=max(0, trace_id - 1))
    for t in traces:
        if t.get("id") == trace_id:
            return jsonify(t)
    return jsonify({"error": "Trace not found"}), 404


@traces_bp.route("/traces/stats", methods=["GET"])
def traces_stats():
    target = request.args.get("target")
    stats = get_trace_stats(target=target)
    return jsonify(stats)
