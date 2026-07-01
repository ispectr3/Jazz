import os
from flask import Flask
from config import Config
from app.extensions import db, jwt, celery_app

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Inicializar extensões
    db.init_app(app)
    jwt.init_app(app)

    # Configurar Celery
    basedir = os.path.abspath(os.path.dirname(__file__))
    celery_app.conf.broker_url = app.config.get("CELERY_BROKER_URL") or f"sqla+sqlite:///{os.path.join(basedir, '..', 'celery_broker.db')}"
    celery_app.conf.result_backend = app.config.get("CELERY_RESULT_BACKEND") or f"db+sqlite:///{os.path.join(basedir, '..', 'celery_results.db')}"

    # Criar tabelas no banco SQLite (inclusive os novos models wireless e hashcat)
    with app.app_context():
        from app.models.base import Role, User, Project, Finding, AuditLog
        from app.models.wireless import WirelessScan, WirelessNetwork, WirelessCapture
        from app.models.hashcat import CrackJob
        db.create_all()

    # Registrar Blueprints
    from app.api.auth import auth_bp
    from app.api.findings import findings_bp
    from app.api.scanner import scanner_bp
    from app.api.wireless import wireless_bp
    from app.api.hashcat import hashcat_bp
    from app.api.debug import debug_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(findings_bp, url_prefix='/api/findings')
    app.register_blueprint(scanner_bp, url_prefix='/api')
    app.register_blueprint(wireless_bp, url_prefix='/api')
    app.register_blueprint(hashcat_bp, url_prefix='/api')
    app.register_blueprint(debug_bp, url_prefix='/debug')

    from flask import render_template
    from flask_cors import CORS

    # Habilita CORS para permitir que o painel HTML chame a API
    CORS(app)

    # Rota raiz servindo o Dashboard Frontend
    @app.route('/')
    def index():
        return render_template("jazznoir-dashboard.html")

    return app
