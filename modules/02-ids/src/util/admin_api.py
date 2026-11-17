from flask import Blueprint, jsonify, request


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.post("/rules/<rule_id>/disable")
def disable_rule(rule_id):
    data = request.get_json(silent=True) or {}
    requested_rule_id = data.get("rule_id", rule_id)

    return jsonify({
        "status": "pending",
        "message": "Desactivación pendiente de implementación",
        "rule_id": requested_rule_id,
    }), 200
