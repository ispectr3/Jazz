"""Celery worker entry point.
Start with: python celery_worker.py [--loglevel=info]
"""
from dotenv import load_dotenv
load_dotenv()

import sys
from app import create_app
from app.extensions import celery_app

# Initialize Flask app to load Celery config
app = create_app()

if __name__ == '__main__':
    argv = sys.argv[1:] if len(sys.argv) > 1 else ["worker", "--loglevel=info", "-Q", "celery"]
    celery_app.start(argv)
