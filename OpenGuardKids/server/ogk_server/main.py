"""Điểm vào cho uvicorn: uvicorn ogk_server.main:app"""
from .app import create_app
app = create_app()
