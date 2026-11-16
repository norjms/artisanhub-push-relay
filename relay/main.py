"""Entry point: uvicorn relay.main:app"""

from .app import create_app

app = create_app()
