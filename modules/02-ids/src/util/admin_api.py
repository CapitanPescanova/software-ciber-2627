import hmac
import os
import re

from flask import Blueprint, jsonify, request


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
VALID_RULES = ("P004", "P005")


@admin_bp.before_request
def protect_admin_api():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        return jsonify({"error": "Admin API solo disponible desde localhost"}), 403

    expected_token = os.getenv("IDS_ADMIN_TOKEN")
    if expected_token:
        authorization = request.headers.get("Authorization", "")
        scheme, _, received_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            received_token, expected_token
        ):
            return jsonify({"error": "Token de administración inválido"}), 401


@admin_bp.get("/rules")
def list_rules():
    return jsonify({"rules": list(VALID_RULES)}), 200


@admin_bp.post("/rules/<rule_id>/disable")
def disable_rule(rule_id):
    if not re.fullmatch(r"P\d{3}", rule_id) or rule_id not in VALID_RULES:
        return jsonify({"error": "Regla inexistente o inválida"}), 404

    data = request.get_json(silent=True) or {}
    requested_rule_id = data.get("rule_id", rule_id)
    if requested_rule_id != rule_id:
        return jsonify({"error": "El identificador de regla no coincide"}), 400

    return jsonify({
        "status": "pending",
        "message": "Desactivación pendiente de implementación",
        "rule_id": requested_rule_id,
    }), 200
