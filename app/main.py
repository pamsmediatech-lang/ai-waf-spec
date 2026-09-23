"""Punkt wejścia: uruchamia AI-WAF jako reverse proxy przed BACKEND_URL.

Uruchomienie: uvicorn app.main:app --port 8080
Zmienna środowiskowa WAF_BACKEND_URL wskazuje chronioną aplikację
(domyślnie http://localhost:8000).
"""
import os

from app.waf.proxy import create_app

app = create_app(backend_url=os.environ.get("WAF_BACKEND_URL", "http://localhost:8000"))
