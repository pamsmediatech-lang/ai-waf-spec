"""Minimalna "chroniona aplikacja" do testów obciążeniowych (spec §12.3).

Nie zawiera żadnej logiki bezpieczeństwa -- celowo, to jest baseline
("gdyby WAF-a tam nie było") do porównania z ruchem przechodzącym przez
AI-WAF. Uruchomienie:

    .venv/Scripts/python -m uvicorn loadtest.backend_stub:app --port 8001
"""
from fastapi import FastAPI, Request

app = FastAPI(title="loadtest-backend")


@app.get("/products")
async def products(request: Request):
    return {"items": ["shoe", "sock", "hat"], "query": dict(request.query_params)}


@app.get("/products/{product_id}")
async def product_detail(product_id: str):
    return {"id": product_id, "name": "widget", "price": 19.99}


@app.get("/search")
async def search(request: Request):
    return {"results": [], "q": request.query_params.get("q", "")}


@app.post("/login")
async def login(request: Request):
    body = await request.body()
    return {"status": "ok", "received_bytes": len(body)}


@app.get("/cart")
async def cart():
    return {"items": []}
