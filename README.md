# Test: Autorizacion biometrica via QR (WebAuthn)

Simula: el usuario X crea una solicitud en su PC -> se genera un QR ->
el jefe escanea el QR con su celular -> el celular pide huella/Face ID
(nativo del navegador, sin apps) -> si es valido, la solicitud queda
aprobada y la PC lo detecta solo (sin recargar).

## 1. Instalar dependencias

```bash
pip install -r requirements.txt --break-system-packages
```

(quita `--break-system-packages` si usas un entorno virtual)

## 2. Deploy en Render (HTTPS publico automatico, sin tocar codigo)

WebAuthn NO funciona entre 2 dispositivos distintos si no hay HTTPS real
(localhost no sirve para esto). `main.py` ya viene listo para Render:
detecta el dominio solo via la variable `RENDER_EXTERNAL_HOSTNAME` que
Render inyecta automaticamente.

1. Sube esta carpeta a un repo de GitHub (puede ser privado):
   ```bash
   git init
   git add .
   git commit -m "test webauthn"
   git branch -M main
   git remote add origin https://github.com/TU-USUARIO/webauthn-test.git
   git push -u origin main
   ```

2. En https://dashboard.render.com → **New** → **Web Service** → conecta el repo.
   Render detecta `render.yaml` solo y precarga:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

   Si no detecta el `render.yaml` automaticamente, pon esos dos comandos
   a mano y elige **Free** como plan.

3. Dale a **Create Web Service**. Cuando termine el deploy (1-3 min),
   te da una URL tipo `https://webauthn-test-xxxx.onrender.com`.

   No necesitas editar `RP_ID` en el codigo, se configura solo.

## Nota sobre el plan free de Render

El plan free "duerme" el servicio tras ~15 min sin trafico. La primera
vez que abras la URL despues de que durmio, tarda unos 30-50 segundos
en despertar (spin-up). Es normal, solo espera. Para un test esto no
es problema; si te molesta, abre la URL un momento antes de hacer la
demo para que ya este "despierto".

## 3. Probar el flujo

1. **PC**: abre `https://TU-APP.onrender.com/`
   Aqui simulas al usuario X. Escribe el detalle y da clic en
   "Crear solicitud y generar QR".

2. **Celular del jefe** (SOLO la primera vez): abre
   `https://TU-APP.onrender.com/registrar-jefe`
   y toca el boton. Te pedira huella/Face ID para registrar el
   autenticador del jefe. Esto se hace una unica vez.

3. Vuelve a la PC, crea una solicitud (paso 1), aparece un QR.
   Escanealo con la camara del celular del jefe (ya registrado).

4. Se abre la pagina de aprobacion en el celular. Toca
   "Autorizar con huella / Face ID". El telefono pide la biometria.

5. La PC detecta automaticamente "APROBADO" en un par de segundos
   (esta haciendo polling cada 1.5s).

## Notas

- Todo se guarda en memoria (diccionarios de Python). Si reinicias el
  servidor, se pierde el registro del jefe y las solicitudes.
- Solo soporta UN jefe registrado a la vez (JEFE_ID fijo), es a proposito
  para simplificar el test. Para produccion habria que:
  - Guardar credenciales en base de datos (tabla `authenticator_credentials`)
  - Soportar multiples aprobadores
  - Agregar expiracion real a las solicitudes (ahora no expiran)
  - Usar WebSockets en vez de polling
  - Para produccion real, este mismo esquema (Render + Uvicorn) sirve,
    solo habria que subir de plan para que no "duerma" el servicio.
