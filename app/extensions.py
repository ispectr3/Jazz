from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from celery import Celery

db = SQLAlchemy()
jwt = JWTManager()

def make_celery(app_name=__name__):
    return Celery(
        app_name,
        task_track_started=True,
        task_ignore_result=False,
    )

celery_app = make_celery()
