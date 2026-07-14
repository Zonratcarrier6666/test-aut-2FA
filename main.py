"""
TEST AISLADO: Autorizacion biometrica (huella/Face ID) via QR
---------------------------------------------------------------
Simula: Usuario X hace una solicitud -> se genera un QR en la PC ->
el Jefe escanea el QR con su celular -> el celular pide huella/rostro
(WebAuthn nativo del navegador, sin apps) -> tanto APROBAR como
RECHAZAR exigen esa verificacion biometrica -> la PC lo detecta
automaticamente (polling).

Todo en memoria (diccionarios). Es SOLO para probar el concepto.
No hay base de datos, no hay persistencia entre reinicios.
"""

import json
import io
import os
import time
import uuid

import qrcode
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)

app = FastAPI(title="Test QR + Biometria (WebAuthn)")

# ============================================================
# CONFIGURACION
# ============================================================
# RP_ID debe ser el dominio (sin protocolo ni puerto) que veran
# TANTO la PC como el celular en la barra de direcciones.
# - En Render: se toma solo automaticamente de RENDER_EXTERNAL_HOSTNAME.
# - Local con ngrok/localtunnel/cloudflared: define la variable de
#   entorno RP_ID antes de correr, o cambia el fallback de abajo.
RP_ID = os.environ.get("RP_ID") or os.environ.get("RENDER_EXTERNAL_HOSTNAME") or "CAMBIA_ESTO.ngrok-free.app"
RP_NAME = "Test Autorizacion Biometrica"
ORIGIN = f"https://{RP_ID}"
PORT = int(os.environ.get("PORT", 8000))

# ============================================================
# "Base de datos" en memoria
# ============================================================
credentials_db = {}        # user_id -> {credential_id, public_key, sign_count}
pending_registration = {}  # user_id -> challenge
pending_auth = {}          # request_id -> challenge

JEFE_ID = "jefe-001"  # fijo para el test; en un sistema real vendria del login

requests_db = {}
# request_id -> {status, solicitante, detalle, created_at, resolved_at, approver}


class NuevaSolicitud(BaseModel):
    solicitante: str
    detalle: str


# ============================================================
# SHELL VISUAL COMPARTIDO (tema HUD / sci-fi)
# ============================================================
FONT_LINKS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;700;900'
    '&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">'
)

BASE_CSS = """
:root{
  --bg:#040509;
  --cyan:#00f0ff;
  --magenta:#ff2bd6;
  --amber:#ffb300;
  --green:#00ff9d;
  --red:#ff3860;
  --text:#dbe7ff;
  --muted:#71809e;
  --border:rgba(0,240,255,0.22);
  --panel:rgba(10,14,26,0.85);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  min-height:100vh;
  background:
    radial-gradient(circle at 15% 10%, rgba(0,240,255,0.10), transparent 42%),
    radial-gradient(circle at 85% 90%, rgba(255,43,214,0.09), transparent 42%),
    var(--bg);
  color:var(--text);
  font-family:'Rajdhani','Segoe UI',sans-serif;
  padding:28px 16px 70px;
  position:relative;
  overflow-x:hidden;
}
body::before{
  content:'';
  position:fixed; inset:0;
  background-image:
    linear-gradient(rgba(0,240,255,0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,240,255,0.035) 1px, transparent 1px);
  background-size:42px 42px;
  pointer-events:none;
  z-index:0;
}
.wrap{position:relative;z-index:1;max-width:480px;margin:0 auto}
.wrap.wide{max-width:960px}
.eyebrow{
  font-family:'Orbitron',sans-serif;font-size:11px;letter-spacing:4px;
  color:var(--cyan);text-transform:uppercase;opacity:0.85;
  display:flex;align-items:center;gap:8px;margin-bottom:6px;
}
h1,h2{
  font-family:'Orbitron','Rajdhani',sans-serif;
  letter-spacing:1.5px;text-transform:uppercase;color:#fff;
  text-shadow:0 0 14px rgba(0,240,255,0.55);
  font-size:1.35rem;margin:0 0 6px;
}
.subtitle{color:var(--muted);font-size:0.85rem;letter-spacing:0.3px;margin-bottom:22px;line-height:1.5}
.panel{
  background:linear-gradient(180deg, rgba(16,20,36,0.85), rgba(6,8,16,0.92));
  border:1px solid var(--border);
  border-radius:16px;
  padding:24px;
  box-shadow:0 0 0 1px rgba(0,240,255,0.04), 0 0 34px rgba(0,240,255,0.07), inset 0 0 50px rgba(0,240,255,0.02);
  position:relative;overflow:hidden;margin-bottom:20px;
}
.panel::before{
  content:'';position:absolute;top:0;left:-120%;width:120%;height:2px;
  background:linear-gradient(90deg, transparent, var(--cyan), transparent);
  animation:scan 4s linear infinite;
}
@keyframes scan{ to{ left:120%; } }
.corner{position:absolute;width:16px;height:16px;border-color:var(--cyan);opacity:0.6}
.corner.tl{top:8px;left:8px;border-top:2px solid;border-left:2px solid}
.corner.tr{top:8px;right:8px;border-top:2px solid;border-right:2px solid}
.corner.bl{bottom:8px;left:8px;border-bottom:2px solid;border-left:2px solid}
.corner.br{bottom:8px;right:8px;border-bottom:2px solid;border-right:2px solid}
label{display:block;font-size:0.72rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
input{
  width:100%;padding:13px 14px;font-size:15px;
  background:rgba(0,0,0,0.4);border:1px solid var(--border);border-radius:9px;
  color:var(--text);font-family:'Rajdhani',sans-serif;margin-bottom:4px;
}
input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 14px rgba(0,240,255,0.35)}
button{
  width:100%;padding:16px;font-size:14px;font-weight:700;letter-spacing:1.8px;text-transform:uppercase;
  border:1px solid var(--cyan);border-radius:11px;
  background:rgba(0,240,255,0.07);color:var(--cyan);cursor:pointer;margin-top:14px;
  transition:all .18s ease;font-family:'Orbitron','Rajdhani',sans-serif;
  position:relative;
}
button:hover{background:rgba(0,240,255,0.18);box-shadow:0 0 20px rgba(0,240,255,0.5);transform:translateY(-1px)}
button:active{transform:translateY(0)}
button:disabled{opacity:0.3;cursor:not-allowed;box-shadow:none;transform:none}
button.danger{border-color:var(--red);color:var(--red);background:rgba(255,56,96,0.07)}
button.danger:hover{background:rgba(255,56,96,0.18);box-shadow:0 0 20px rgba(255,56,96,0.5)}
button.ghost{border-color:var(--border);color:var(--muted);background:transparent;box-shadow:none}
a{color:var(--cyan);text-decoration:none;letter-spacing:0.3px}
a:hover{text-decoration:underline}
.back-link{display:inline-block;margin-bottom:18px;font-size:0.85rem;color:var(--muted)}
.back-link:hover{color:var(--cyan)}
#status,#msg{
  margin-top:18px;padding:15px;border-radius:11px;font-weight:700;font-family:'Orbitron','Rajdhani',sans-serif;
  letter-spacing:0.5px;text-align:center;border:1px solid transparent;font-size:0.85rem;min-height:1px;
}
.pending{background:rgba(255,179,0,0.09);color:var(--amber);border-color:rgba(255,179,0,0.4)}
.approved{background:rgba(0,255,157,0.09);color:var(--green);border-color:rgba(0,255,157,0.4)}
.rejected{background:rgba(255,56,96,0.09);color:var(--red);border-color:rgba(255,56,96,0.4)}
.qr-frame{
  margin-top:20px;padding:22px;text-align:center;
  border:1px solid var(--border);border-radius:16px;
  background:rgba(0,0,0,0.35);box-shadow:0 0 34px rgba(0,240,255,0.14);
  position:relative;
}
.qr-frame img{border-radius:10px;box-shadow:0 0 24px rgba(0,240,255,0.35);display:block;margin:0 auto}
.req-id{font-size:10px;color:var(--muted);margin-top:12px;letter-spacing:1px;word-break:break-all;font-family:monospace}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:13px 10px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--muted);text-transform:uppercase;font-size:10.5px;letter-spacing:1.5px;font-weight:600;font-family:'Orbitron',sans-serif}
tr:hover td{background:rgba(0,240,255,0.035)}
.empty{text-align:center;color:var(--muted);padding:50px 0;font-size:0.9rem;letter-spacing:0.5px}
.top-nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;flex-wrap:wrap;gap:10px}
.pulse-dot{
  display:inline-block;width:8px;height:8px;border-radius:50%;
  background:var(--cyan);box-shadow:0 0 10px var(--cyan);
  animation:pulse 1.4s ease-in-out infinite;flex-shrink:0;
}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.25}}
.detalle-box{
  background:rgba(0,0,0,0.35);border:1px solid var(--border);border-radius:11px;
  padding:16px;margin-top:16px;text-align:left;font-size:14.5px;line-height:1.5;
}
.detalle-box b{color:var(--cyan);text-transform:uppercase;font-size:10.5px;letter-spacing:1.5px;
  display:block;margin-bottom:7px;font-family:'Orbitron',sans-serif}
.scanline{
  position:fixed;left:0;right:0;height:2px;top:0;
  background:linear-gradient(90deg, transparent, rgba(0,240,255,0.5), transparent);
  animation:scanline 6s linear infinite;pointer-events:none;z-index:5;
}
@keyframes scanline{ 0%{top:0} 100%{top:100vh} }
.btn-row{display:flex;gap:10px}
.btn-row button{margin-top:14px}
"""


def page_shell(title: str, body_html: str, wide: bool = False) -> str:
    wrap_class = "wrap wide" if wide else "wrap"
    return f"""<!DOCTYPE html>
<html><head><title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
{FONT_LINKS}
<style>{BASE_CSS}</style>
</head><body>
<div class="scanline"></div>
<div class="{wrap_class}">
{body_html}
</div>
</body></html>"""


WEBAUTHN_HELPERS_JS = """
function b64uToBuf(b64u){
    const pad = '='.repeat((4 - b64u.length % 4) % 4);
    const b64 = (b64u + pad).replace(/-/g,'+').replace(/_/g,'/');
    const raw = atob(b64);
    const buf = new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++) buf[i]=raw.charCodeAt(i);
    return buf;
}
function bufToB64u(buf){
    const bytes = new Uint8Array(buf);
    let str='';
    for(const b of bytes) str+=String.fromCharCode(b);
    return btoa(str).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
}
"""


# ============================================================
# PAGINA 1: PC - crea solicitudes y muestra el QR
# ============================================================
@app.get("/", response_class=HTMLResponse)
def home():
    body = """
    <div class="eyebrow"><span class="pulse-dot"></span>TERMINAL DE SOLICITUDES</div>
    <h2>Usuario X · Panel de acceso</h2>
    <div class="subtitle">Genera una solicitud y autentica al aprobador via QR + biometria.</div>

    <div class="panel">
      <span class="corner tl"></span><span class="corner tr"></span>
      <span class="corner bl"></span><span class="corner br"></span>
      <label>Detalle de la solicitud</label>
      <input id="detalle" value="Aprobar compra de material - $50,000">
      <button onclick="crearSolicitud()">▶ Generar solicitud + QR</button>
      <div id="qr"></div>
      <div id="status"></div>
    </div>

    <p style="text-align:center"><a href="/historial">📋 Ver historial de solicitudes</a></p>

    <script>
    let requestId = null;
    let poller = null;

    async function crearSolicitud(){
        const detalle = document.getElementById('detalle').value;
        const resp = await fetch('/api/request/create', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({solicitante:'usuario-x', detalle})
        });
        const data = await resp.json();
        requestId = data.request_id;
        document.getElementById('qr').innerHTML =
            `<div class="qr-frame">
                <div class="eyebrow" style="justify-content:center">ESCANEAR PARA AUTORIZAR</div>
                <img src="/qr/${requestId}" width="240">
                <div class="req-id">ID: ${requestId}</div>
             </div>`;
        const st = document.getElementById('status');
        st.className = 'pending';
        st.innerText = '◌ ESPERANDO VERIFICACION BIOMETRICA...';
        if(poller) clearInterval(poller);
        poller = setInterval(checkStatus, 1500);
    }

    async function checkStatus(){
        if(!requestId) return;
        const resp = await fetch(`/api/request/${requestId}/status`);
        const data = await resp.json();
        const el = document.getElementById('status');
        if(data.status === 'approved'){
            el.className='approved';
            el.innerText='✅ AUTORIZADO POR BIOMETRIA DEL JEFE';
            clearInterval(poller);
        } else if(data.status === 'rejected'){
            el.className='rejected';
            el.innerText='❌ RECHAZADO POR EL JEFE';
            clearInterval(poller);
        }
    }
    </script>
    """
    return page_shell("Usuario X · Terminal", body)


@app.post("/api/request/create")
def crear_solicitud(s: NuevaSolicitud):
    request_id = str(uuid.uuid4())
    requests_db[request_id] = {
        "status": "pending",
        "solicitante": s.solicitante,
        "detalle": s.detalle,
        "created_at": time.time(),
        "resolved_at": None,
        "approver": None,
    }
    return {"request_id": request_id}


@app.get("/api/request/{request_id}/status")
def status_solicitud(request_id: str):
    r = requests_db.get(request_id)
    if not r:
        raise HTTPException(404, "No existe")
    return {"status": r["status"], "detalle": r["detalle"]}


@app.get("/qr/{request_id}")
def qr_solicitud(request_id: str):
    if request_id not in requests_db:
        raise HTTPException(404, "No existe")
    url = f"{ORIGIN}/approve/{request_id}"
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ============================================================
# PAGINA 2: CELULAR DEL JEFE - registro (una sola vez)
# ============================================================
@app.get("/registrar-jefe", response_class=HTMLResponse)
def registrar_jefe_page():
    body = f"""
    <div class="eyebrow"><span class="pulse-dot"></span>ENROLAMIENTO BIOMETRICO</div>
    <h2>Registro del jefe</h2>
    <div class="subtitle">Se hace <b>una sola vez</b>. Vincula la huella/rostro de este
    telefono como autenticador oficial del aprobador.</div>

    <div class="panel" style="text-align:center">
      <span class="corner tl"></span><span class="corner tr"></span>
      <span class="corner bl"></span><span class="corner br"></span>
      <button onclick="registrar()">🔐 Registrar con huella / Face ID</button>
      <div id="msg"></div>
    </div>

    <script>
    {WEBAUTHN_HELPERS_JS}
    async function registrar(){{
        const msg = document.getElementById('msg');
        try{{
            const beginResp = await fetch('/api/register/begin', {{method:'POST'}});
            const options = await beginResp.json();
            if(!beginResp.ok){{
                throw new Error(options.detail || 'Error del servidor al iniciar registro');
            }}

            options.challenge = b64uToBuf(options.challenge);
            options.user.id = b64uToBuf(options.user.id);
            if(options.excludeCredentials){{
                options.excludeCredentials = options.excludeCredentials.map(c => ({{
                    ...c, id: b64uToBuf(c.id)
                }}));
            }}

            const cred = await navigator.credentials.create({{publicKey: options}});

            const payload = {{
                id: cred.id,
                rawId: bufToB64u(cred.rawId),
                type: cred.type,
                response: {{
                    clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                    attestationObject: bufToB64u(cred.response.attestationObject),
                }}
            }};

            const completeResp = await fetch('/api/register/complete', {{
                method:'POST', headers:{{'Content-Type':'application/json'}},
                body: JSON.stringify(payload)
            }});
            const result = await completeResp.json();
            if(result.ok){{
                msg.className = 'approved';
                msg.innerText = '✅ REGISTRADO CORRECTAMENTE';
            }} else {{
                msg.className = 'rejected';
                msg.innerText = '❌ ERROR: ' + JSON.stringify(result);
            }}
        }} catch(e){{
            msg.className = 'rejected';
            msg.innerText = '❌ ' + e.message + ' (¿https y sensor biometrico?)';
        }}
    }}
    </script>
    """
    return page_shell("Registro del jefe", body)


@app.post("/api/register/begin")
def register_begin():
    user_id_bytes = JEFE_ID.encode()
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id_bytes,
        user_name="jefe",
        user_display_name="Jefe (aprobador)",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    pending_registration[JEFE_ID] = options.challenge
    return JSONResponse(content=json.loads(options_to_json(options)))


@app.post("/api/register/complete")
async def register_complete(request: Request):
    body = await request.json()
    expected_challenge = pending_registration.get(JEFE_ID)
    if not expected_challenge:
        raise HTTPException(400, "No hay registro pendiente")
    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}

    credentials_db[JEFE_ID] = {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    }
    del pending_registration[JEFE_ID]
    return {"ok": True}


# ============================================================
# PAGINA 3: CELULAR DEL JEFE - aprobar/rechazar una solicitud (via QR)
# Tanto aprobar como rechazar exigen la misma verificacion biometrica.
# ============================================================
@app.get("/approve/{request_id}", response_class=HTMLResponse)
def approve_page(request_id: str):
    if request_id not in requests_db:
        body = """
        <div class="eyebrow"><span class="pulse-dot"></span>ERROR</div>
        <h2>Solicitud no encontrada</h2>
        <div class="panel"><div class="subtitle">El enlace expiro o no existe.</div></div>
        """
        return HTMLResponse(page_shell("No encontrada", body), status_code=404)

    r = requests_db[request_id]
    detalle = r["detalle"]

    if r["status"] != "pending":
        estado_txt = {"approved": "✅ YA FUE APROBADA", "rejected": "❌ YA FUE RECHAZADA"}.get(
            r["status"], r["status"]
        )
        css_class = "approved" if r["status"] == "approved" else "rejected"
        body = f"""
        <div class="eyebrow"><span class="pulse-dot"></span>SOLICITUD RESUELTA</div>
        <h2>Estado final</h2>
        <div class="panel">
          <span class="corner tl"></span><span class="corner tr"></span>
          <span class="corner bl"></span><span class="corner br"></span>
          <div id="status" class="{css_class}">{estado_txt}</div>
          <div class="detalle-box"><b>Detalle</b>{detalle}</div>
        </div>
        <p style="text-align:center"><a href="/historial">Ver historial completo</a></p>
        """
        return page_shell("Solicitud resuelta", body)

    body = f"""
    <div class="eyebrow"><span class="pulse-dot"></span>VERIFICACION REQUERIDA</div>
    <h2>Solicitud de autorizacion</h2>

    <div class="panel">
      <span class="corner tl"></span><span class="corner tr"></span>
      <span class="corner bl"></span><span class="corner br"></span>
      <div class="detalle-box"><b>Detalle</b>{detalle}</div>
      <div class="btn-row">
        <button onclick="resolver('approve')">🔓 Autorizar</button>
        <button class="danger" onclick="resolver('reject')">✖ Rechazar</button>
      </div>
      <div class="subtitle" style="margin:10px 0 0;text-align:center">
        Ambas acciones piden huella / Face ID
      </div>
      <div id="msg"></div>
    </div>

    <script>
    {WEBAUTHN_HELPERS_JS}
    async function resolver(accion){{
        const msg = document.getElementById('msg');
        msg.className = '';
        msg.innerText = '◌ Esperando verificacion biometrica...';
        try{{
            const beginResp = await fetch('/api/auth/begin/{request_id}', {{method:'POST'}});
            const options = await beginResp.json();
            if(!beginResp.ok){{
                throw new Error(options.detail || 'Error del servidor al iniciar verificacion');
            }}
            options.challenge = b64uToBuf(options.challenge);
            if(options.allowCredentials){{
                options.allowCredentials = options.allowCredentials.map(c => ({{
                    ...c, id: b64uToBuf(c.id)
                }}));
            }}

            const assertion = await navigator.credentials.get({{publicKey: options}});

            const payload = {{
                action: accion,
                id: assertion.id,
                rawId: bufToB64u(assertion.rawId),
                type: assertion.type,
                response: {{
                    clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
                    authenticatorData: bufToB64u(assertion.response.authenticatorData),
                    signature: bufToB64u(assertion.response.signature),
                }}
            }};

            const completeResp = await fetch('/api/auth/complete/{request_id}', {{
                method:'POST', headers:{{'Content-Type':'application/json'}},
                body: JSON.stringify(payload)
            }});
            const result = await completeResp.json();
            if(result.ok){{
                if(accion === 'approve'){{
                    msg.className = 'approved';
                    msg.innerText = '✅ AUTORIZADO CORRECTAMENTE';
                }} else {{
                    msg.className = 'rejected';
                    msg.innerText = '❌ SOLICITUD RECHAZADA';
                }}
                document.querySelectorAll('button').forEach(b => b.disabled = true);
            }} else {{
                msg.className = 'rejected';
                msg.innerText = '⚠️ ' + (result.error || 'Error de verificacion');
            }}
        }} catch(e){{
            msg.className = 'rejected';
            msg.innerText = '⚠️ ' + e.message;
        }}
    }}
    </script>
    """
    return page_shell("Autorizar solicitud", body)


@app.post("/api/auth/begin/{request_id}")
def auth_begin(request_id: str):
    if request_id not in requests_db:
        raise HTTPException(404, "Solicitud no existe")
    if requests_db[request_id]["status"] != "pending":
        raise HTTPException(400, "Esta solicitud ya fue resuelta")
    if JEFE_ID not in credentials_db:
        raise HTTPException(400, "El jefe no ha registrado su biometria. Ve a /registrar-jefe primero")

    cred = credentials_db[JEFE_ID]
    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=cred["credential_id"])
        ],
    )
    pending_auth[request_id] = options.challenge
    return JSONResponse(content=json.loads(options_to_json(options)))


@app.post("/api/auth/complete/{request_id}")
async def auth_complete(request_id: str, request: Request):
    body = await request.json()
    action = body.pop("action", "approve")
    if action not in ("approve", "reject"):
        raise HTTPException(400, "Accion invalida")

    if request_id not in requests_db:
        raise HTTPException(404, "Solicitud no existe")
    if requests_db[request_id]["status"] != "pending":
        raise HTTPException(400, "Esta solicitud ya fue resuelta")

    expected_challenge = pending_auth.get(request_id)
    if not expected_challenge:
        raise HTTPException(400, "No hay verificacion pendiente para esta solicitud")

    cred = credentials_db[JEFE_ID]
    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=cred["public_key"],
            credential_current_sign_count=cred["sign_count"],
        )
    except Exception as e:
        # La huella no fue valida: no resolvemos la solicitud, se puede reintentar
        del pending_auth[request_id]
        return {"ok": False, "error": str(e)}

    cred["sign_count"] = verification.new_sign_count
    # La biometria fue valida -> se aplica la accion que el jefe eligio (aprobar o rechazar)
    requests_db[request_id]["status"] = "approved" if action == "approve" else "rejected"
    requests_db[request_id]["approver"] = JEFE_ID
    requests_db[request_id]["resolved_at"] = time.time()
    del pending_auth[request_id]
    return {"ok": True, "action": action}


@app.get("/api/request/all")
def listar_solicitudes():
    out = []
    for rid, r in sorted(requests_db.items(), key=lambda kv: kv[1]["created_at"], reverse=True):
        out.append({
            "id": rid,
            "status": r["status"],
            "solicitante": r["solicitante"],
            "detalle": r["detalle"],
            "created_at": r["created_at"],
            "resolved_at": r.get("resolved_at"),
            "approver": r.get("approver"),
        })
    return out


# ============================================================
# PAGINA 4: HISTORIAL - todas las solicitudes, su estado y quien resolvio
# ============================================================
@app.get("/historial", response_class=HTMLResponse)
def historial_page():
    body = """
    <div class="top-nav">
      <div>
        <div class="eyebrow"><span class="pulse-dot"></span>REGISTRO DE AUDITORIA</div>
        <h2 style="margin-bottom:0">Historial de solicitudes</h2>
      </div>
      <a class="back-link" href="/">← Nueva solicitud</a>
    </div>

    <div class="panel">
      <span class="corner tl"></span><span class="corner tr"></span>
      <span class="corner bl"></span><span class="corner br"></span>
      <div id="empty" class="empty" style="display:none">— SIN REGISTROS AUN —</div>
      <table id="tabla" style="display:none">
        <thead><tr>
          <th>Detalle</th><th>Solicitante</th><th>Estado</th>
          <th>Creada</th><th>Resuelta</th><th>Por</th>
        </tr></thead>
        <tbody id="filas"></tbody>
      </table>
    </div>

    <script>
    const estadoTxt = {pending:'⏳ PENDIENTE', approved:'✅ APROBADA', rejected:'❌ RECHAZADA'};

    function fmt(ts){
        if(!ts) return '—';
        return new Date(ts*1000).toLocaleString();
    }

    async function cargar(){
        const resp = await fetch('/api/request/all');
        const data = await resp.json();
        const tabla = document.getElementById('tabla');
        const vacio = document.getElementById('empty');
        const filas = document.getElementById('filas');
        if(data.length === 0){
            tabla.style.display='none'; vacio.style.display='block'; return;
        }
        vacio.style.display='none'; tabla.style.display='table';
        filas.innerHTML = data.map(r => `
            <tr>
                <td>${r.detalle}</td>
                <td>${r.solicitante}</td>
                <td class="${r.status}" style="font-weight:700">${estadoTxt[r.status] || r.status}</td>
                <td>${fmt(r.created_at)}</td>
                <td>${fmt(r.resolved_at)}</td>
                <td>${r.approver || '—'}</td>
            </tr>
        `).join('');
    }

    cargar();
    setInterval(cargar, 3000);
    </script>
    """
    return page_shell("Historial de solicitudes", body, wide=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)