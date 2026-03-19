"""
JonCheats — Servidor Webhook Mercado Pago
Deploy no Railway: https://railway.app
Variáveis de ambiente necessárias:
  MP_ACCESS_TOKEN   = APP_USR-...
  SUPABASE_URL      = https://xxx.supabase.co
  SUPABASE_KEY      = service_role key
  WEBHOOK_SECRET    = string aleatória que você define (ex: joncheatssecret123)
"""
import os
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

MP_ACCESS_TOKEN = os.environ.get("MP_ACCESS_TOKEN", "")
SUPABASE_URL    = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY    = os.environ.get("SUPABASE_KEY", "")
WEBHOOK_SECRET  = os.environ.get("WEBHOOK_SECRET", "")

HEADERS_MP = {
    "Authorization": f"Bearer {MP_ACCESS_TOKEN}",
    "Content-Type":  "application/json",
}
HEADERS_SB = {
    "apikey":        SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type":  "application/json",
}

def buscar_pagamento_mp(payment_id):
    r = requests.get(f"https://api.mercadopago.com/v1/payments/{payment_id}", headers=HEADERS_MP, timeout=10)
    return r.json() if r.status_code == 200 else None

def atualizar_usuario(username, plano, dias):
    url = f"{SUPABASE_URL}/rest/v1/users?username=eq.{username}&select=expires_at,plano"
    r = requests.get(url, headers=HEADERS_SB, timeout=10)
    if r.status_code != 200 or not r.json():
        return False

    usuario = r.json()[0]
    expires_atual = usuario.get("expires_at")
    plano_atual   = usuario.get("plano", "free")

    # Calcula nova data — se já tem dias futuros, soma em cima
    try:
        base = datetime.fromisoformat(expires_atual.replace("Z", "+00:00"))
        if base < datetime.now(timezone.utc):
            base = datetime.now(timezone.utc)
    except:
        base = datetime.now(timezone.utc)

    nova_expiracao = (base + timedelta(days=dias)).isoformat()

    # Hierarquia de planos — nunca faz downgrade
    HIERARQUIA = {"free": 0, "trial": 0, "premium": 1, "vip": 2}
    novo_plano = plano if HIERARQUIA.get(plano, 0) >= HIERARQUIA.get(plano_atual, 0) else plano_atual

    patch_url = f"{SUPABASE_URL}/rest/v1/users?username=eq.{username}"
    r2 = requests.patch(patch_url, headers=HEADERS_SB, json={
        "plano":      novo_plano,
        "expires_at": nova_expiracao,
        "active":     True,
    }, timeout=10)
    return r2.status_code in (200, 204)

@app.route("/webhook", methods=["POST"])
def webhook():
    # Valida assinatura do MP (x-signature header)
    sig_header = request.headers.get("x-signature", "")
    ts = ""
    v1 = ""
    for part in sig_header.split(","):
        if part.startswith("ts="):
            ts = part[3:]
        if part.startswith("v1="):
            v1 = part[3:]

    request_id = request.headers.get("x-request-id", "")
    data_id    = request.args.get("data.id", "")
    manifest   = f"id:{data_id};request-id:{request_id};ts:{ts};"

    expected = hmac.new(WEBHOOK_SECRET.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        return jsonify({"error": "invalid signature"}), 401

    body = request.get_json(silent=True) or {}
    if body.get("type") != "payment":
        return jsonify({"ok": True}), 200

    payment_id = body.get("data", {}).get("id")
    if not payment_id:
        return jsonify({"ok": True}), 200

    pag = buscar_pagamento_mp(payment_id)
    if not pag or pag.get("status") != "approved":
        return jsonify({"ok": True}), 200

    # Lê metadata que o trainer enviou
    meta     = pag.get("metadata", {})
    username = meta.get("username")
    plano    = meta.get("plano")
    dias     = int(meta.get("dias", 0))

    if not username or not plano or not dias:
        return jsonify({"error": "missing metadata"}), 400

    ok = atualizar_usuario(username, plano, dias)
    return jsonify({"ok": ok}), 200 if ok else 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
