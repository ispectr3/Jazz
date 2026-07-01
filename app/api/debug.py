from flask import Blueprint, request, jsonify

debug_bp = Blueprint('debug', __name__)

@debug_bp.route('/inspect', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def inspecionar_requisicao():
    dados = {
        "metodo": request.method,
        "url_completa": request.url,
        "headers": dict(request.headers),
        "parametros_get_url": dict(request.args),
    }

    if request.method == 'POST':
        if request.is_json:
            dados["payload_post_json"] = request.get_json()
        elif request.form:
            dados["payload_post_formulario"] = dict(request.form)
        else:
            dados["payload_post_bruto"] = request.data.decode('utf-8', errors='ignore')

    return jsonify(dados), 200
