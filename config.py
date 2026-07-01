import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-change-me'
    
    # Banco de Dados agora é um arquivo local (SQLite), 100% standalone
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'jazznoir.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-super-secret-key'
    
    # Celery vai usar o próprio SQLite como broker e backend, removendo a necessidade do Redis
    CELERY_BROKER_URL = 'sqla+sqlite:///' + os.path.join(basedir, 'celery_broker.db')
    CELERY_RESULT_BACKEND = 'db+sqlite:///' + os.path.join(basedir, 'celery_results.db')
