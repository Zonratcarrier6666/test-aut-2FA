"""
TEST AISLADO: Autorización biométrica (huella/Face ID) vía QR
---------------------------------------------------------------
Simula: Usuario X hace una solicitud -> se genera un QR en la PC ->
el Jefe escanea el QR con su celular -> el celular pide huella/rostro
(WebAuthn nativo del navegador, sin apps) -> si es válido, la solicitud
queda "aprobada" y la PC lo detecta automáticamente (polling).

Todo en memoria (diccionarios). Es SOLO para probar el concepto.
No hay base de datos, no hay persistencia entre reinicios.
"""

import base64
import io
import os
import secrets
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
from webauthn.helpers import base64url_to_bytes

app = FastAPI(title="Test QR + Biometria (WebAuthn)")

# ============================================================
# CONFIGURACION
# ============================================================
# RP_ID debe ser el dominio (sin protocolo ni puerto) que verán
# TANTO la PC como el celular en la barra de direcciones.
# - En Render: se toma solo automaticamente de RENDER_EXTERNAL_HOSTNAME,
#   que Render inyecta solo. No hay que tocar nada.
# - Local con ngrok/localtunnel: define la variable de entorno RP_ID
#   antes de correr, o cambia el fallback de abajo.
# - WebAuthn EXIGE https (salvo "localhost" exacto, que no sirve para 2 dispositivos)
RP_ID = os.environ.get("RP_ID") or os.environ.get("RENDER_EXTERNAL_HOSTNAME") or "CAMBIA_ESTO.ngrok-free.app"
RP_NAME = "Test Autorizacion Biometrica"
ORIGIN = f"https://{RP_ID}"
PORT = int(os.environ.get("PORT", 8000))

# ============================================================
# "Base de datos" en memoria
# ============================================================
credentials_db = {}   # user_id -> {credential_id, public_key, sign_count, name}
pending_registration = {}  # user_id -> challenge
pending_auth = {}  # request_id -> challenge

# jefe_id fijo para el test (en un sistema real vendria del login)
JEFE_ID = "jefe-001"

requests_db = {}
# request_id -> {status: pending/approved/rejected/expired, requester, created_at, approver}


class NuevaSolicitud(BaseModel):
    solicitante: str
    detalle: str


# ============================================================
# PAGINA 1: PC - crea solicitudes y muestra el QR
# ============================================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html><head><title>PC - Usuario X</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body{font-family:sans-serif;max-width:480px;margin:40px auto;padding:0 16px}
      button{padding:14px 20px;font-size:16px;cursor:pointer;width:100%;margin-top:10px}
      #qr{margin-top:20px;text-align:center}
      #status{margin-top:16px;padding:12px;border-radius:8px;font-weight:bold}
      .pending{background:#fff3cd}
      .approved{background:#d4edda;color:#155724}
      .rejected{background:#f8d7da;color:#721c24}
      input{width:100%;padding:10px;font-size:16px;margin-top:6px;box-sizing:border-box}
    </style>
    </head><body>
    <h2>🖥️ PC - Usuario X</h2>
    <p>Simula que el usuario X necesita autorizacion del jefe para algo.</p>
    <label>Detalle de la solicitud:</label>
    <input id="detalle" value="Aprobar compra de material - $50,000">
    <button onclick="crearSolicitud()">Crear solicitud y generar QR</button>

    <div id="qr"></div>
    <div id="status"></div>

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
            `<p>Escanea con el celular del <b>jefe</b>:</p>
             <img src="/qr/${requestId}" width="260">
             <p style="font-size:12px;color:#666">Request ID: ${requestId}</p>`;
        document.getElementById('status').className = 'pending';
        document.getElementById('status').innerText = '⏳ Esperando autorizacion...';
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
            el.innerText='✅ APROBADO por biometria del jefe';
            clearInterval(poller);
        } else if(data.status === 'rejected'){
            el.className='rejected';
            el.innerText='❌ Rechazado / fallo de verificacion';
            clearInterval(poller);
        }
    }
    </script>
    </body></html>
    """


@app.post("/api/request/create")
def crear_solicitud(s: NuevaSolicitud):
    request_id = str(uuid.uuid4())
    requests_db[request_id] = {
        "status": "pending",
        "solicitante": s.solicitante,
        "detalle": s.detalle,
        "created_at": time.time(),
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
    return """
    <html><head><title>Registro biometrico - Jefe</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body{font-family:sans-serif;max-width:420px;margin:40px auto;padding:0 16px;text-align:center}
    button{padding:16px;font-size:18px;width:100%;margin-top:20px}</style>
    </head><body>
    <h2>👔 Registro del Jefe</h2>
    <p>Esto se hace <b>una sola vez</b>. Registra la huella/rostro de este telefono
    como el autenticador oficial del jefe.</p>
    <button onclick="registrar()">Registrar con huella / Face ID</button>
    <p id="msg"></p>

    <script>
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

    async function registrar(){
        const msg = document.getElementById('msg');
        try{
            const beginResp = await fetch('/api/register/begin', {method:'POST'});
            const options = await beginResp.json();
            if(!beginResp.ok){
                throw new Error(options.detail || 'Error del servidor al iniciar registro');
            }

            options.challenge = b64uToBuf(options.challenge);
            options.user.id = b64uToBuf(options.user.id);
            if(options.excludeCredentials){
                options.excludeCredentials = options.excludeCredentials.map(c => ({
                    ...c, id: b64uToBuf(c.id)
                }));
            }

            const cred = await navigator.credentials.create({publicKey: options});

            const payload = {
                id: cred.id,
                rawId: bufToB64u(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                    attestationObject: bufToB64u(cred.response.attestationObject),
                }
            };

            const completeResp = await fetch('/api/register/complete', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify(payload)
            });
            const result = await completeResp.json();
            if(result.ok){
                msg.innerText = '✅ Registrado correctamente. Ya puedes aprobar solicitudes.';
            } else {
                msg.innerText = '❌ Error: ' + JSON.stringify(result);
            }
        } catch(e){
            msg.innerText = '❌ ' + e.message + ' (¿estas en https y con sensor biometrico?)';
        }
    }
    </script>
    </body></html>
    """


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
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    pending_registration[JEFE_ID] = options.challenge
    return JSONResponse(content=__import__("json").loads(options_to_json(options)))


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
# PAGINA 3: CELULAR DEL JEFE - aprobar una solicitud especifica (via QR)
# ============================================================
@app.get("/approve/{request_id}", response_class=HTMLResponse)
def approve_page(request_id: str):
    if request_id not in requests_db:
        return HTMLResponse("<h3>Solicitud no encontrada o expirada</h3>", status_code=404)
    detalle = requests_db[request_id]["detalle"]
    return f"""
    <html><head><title>Aprobar solicitud</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body{{font-family:sans-serif;max-width:420px;margin:40px auto;padding:0 16px;text-align:center}}
    button{{padding:16px;font-size:18px;width:100%;margin-top:20px;background:#2e7d32;color:white;border:none;border-radius:8px}}
    .detalle{{background:#f0f0f0;padding:14px;border-radius:8px;margin-top:16px;text-align:left}}
    </style>
    </head><body>
    <h2>📱 Solicitud de autorizacion</h2>
    <div class="detalle"><b>Detalle:</b><br>{detalle}</div>
    <button onclick="aprobar()">🔐 Autorizar con huella / Face ID</button>
    <p id="msg"></p>

    <script>
    function b64uToBuf(b64u){{
        const pad = '='.repeat((4 - b64u.length % 4) % 4);
        const b64 = (b64u + pad).replace(/-/g,'+').replace(/_/g,'/');
        const raw = atob(b64);
        const buf = new Uint8Array(raw.length);
        for(let i=0;i<raw.length;i++) buf[i]=raw.charCodeAt(i);
        return buf;
    }}
    function bufToB64u(buf){{
        const bytes = new Uint8Array(buf);
        let str='';
        for(const b of bytes) str+=String.fromCharCode(b);
        return btoa(str).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    }}

    async function aprobar(){{
        const msg = document.getElementById('msg');
        try{{
            const beginResp = await fetch('/api/auth/begin/{request_id}', {{method:'POST'}});
            const options = await beginResp.json();
            if(!beginResp.ok){{
                throw new Error(options.detail || 'Error del servidor al iniciar autenticacion');
            }}
            options.challenge = b64uToBuf(options.challenge);
            if(options.allowCredentials){{
                options.allowCredentials = options.allowCredentials.map(c => ({{
                    ...c, id: b64uToBuf(c.id)
                }}));
            }}

            const assertion = await navigator.credentials.get({{publicKey: options}});

            const payload = {{
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
            msg.innerText = result.ok ? '✅ Autorizado correctamente' : ('❌ ' + result.error);
        }} catch(e){{
            msg.innerText = '❌ ' + e.message;
        }}
    }}
    </script>
    </body></html>
    """


@app.post("/api/auth/begin/{request_id}")
def auth_begin(request_id: str):
    if request_id not in requests_db:
        raise HTTPException(404, "Solicitud no existe")
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
    return JSONResponse(content=__import__("json").loads(options_to_json(options)))


@app.post("/api/auth/complete/{request_id}")
async def auth_complete(request_id: str, request: Request):
    body = await request.json()
    if request_id not in requests_db:
        raise HTTPException(404, "Solicitud no existe")
    expected_challenge = pending_auth.get(request_id)
    if not expected_challenge:
        raise HTTPException(400, "No hay auth pendiente para esta solicitud")

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
        requests_db[request_id]["status"] = "rejected"
        return {"ok": False, "error": str(e)}

    cred["sign_count"] = verification.new_sign_count
    requests_db[request_id]["status"] = "approved"
    requests_db[request_id]["approver"] = JEFE_ID
    del pending_auth[request_id]
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
