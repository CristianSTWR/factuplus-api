# main.py (PostgreSQL + SQLAlchemy AsyncSession) — REPARADO

from datetime import datetime, timedelta, timezone
import logging
import os
import secrets
import hashlib
import uuid
import json
import string
import jwt
from jose import jwt, JWTError
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from dateutil.relativedelta import relativedelta
from sqlalchemy.dialects.postgresql import insert
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Form, Query, WebSocket, UploadFile, File, Cookie, Header
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from sqlalchemy import select, and_, func, case, asc, update
from sqlalchemy.exc import DBAPIError
import base64
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.cors import CORSMiddleware
from decimal import Decimal
from starlette.middleware.trustedhost import TrustedHostMiddleware
from dateutil import parser
from passlib.context import CryptContext
import random
from zoneinfo import ZoneInfo


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)



from config import (
    APP_ENV,
    IS_PROD,
    JWT_SECRET,
    JWT_ALGORITHM,
    ACCESS_MINUTES,
    REFRESH_DAYS,
    PAYPAL_BASE_URL,
    PAYPAL_CLIENT_ID,
    PAYPAL_CLIENT_SECRET,
    PAYPAL_RETURN_URL,
    PAYPAL_CANCEL_URL,
    PAYPAL_WEBHOOK_ID,
    VERIFY_PAYPAL_WEBHOOKS,
    ALLOWED_ORIGINS,
    ALLOWED_HOSTS,
    MAX_BODY_BYTES,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_APP_PASSWORD,
    EMAIL_FROM,
    validate_settings,
)

from security_middleware import SecurityHeadersMiddleware, RequestIdMiddleware, MaxBodySizeMiddleware
from rate_limit import TokenBucketLimiter
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse, parse_qs
import httpx
import re
# APLICACION
from models import Planes, PaypalEnv, License, PaypalWebhookEvent, Company, User, CajaConfig, CajaMovimiento, Venta, Caja, Producto, UnidadMedida

# WEB
from models import ListaEspera, EmpresaDispositivo

from db import get_db

load_dotenv()
validate_settings()

# logging
logging.basicConfig(level=(logging.INFO if IS_PROD else logging.DEBUG))
logger = logging.getLogger("factuplus")

# FastAPI (docs off in prod)
_docs = None if IS_PROD else "/docs"
_redoc = None if IS_PROD else "/redoc"
app = FastAPI(title="FACTUPLUS Licensing API", docs_url=_docs, redoc_url=_redoc)

# Middlewares
app.add_middleware(RequestIdMiddleware)
app.add_middleware(MaxBodySizeMiddleware, max_bytes=MAX_BODY_BYTES)
app.add_middleware(SecurityHeadersMiddleware, is_prod=IS_PROD)

# CORS (set ALLOWED_ORIGINS in env). If empty, do not enable permissive CORS.
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Internal-Key", "X-Request-Id"],
    )

# Allowed hosts (recommended in prod). If empty, allow all.
if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS) 


# Simple in-memory rate limiters (recommended to offload to WAF in production)
#  - sensitive endpoints: 1 req/sec with burst 10 per IP
limiter_sensitive = TokenBucketLimiter(rate_per_sec=1.0, burst=10)
#  - webhook: allow higher, but still avoid abuse
limiter_webhook = TokenBucketLimiter(rate_per_sec=5.0, burst=50)

def _client_ip(request: Request) -> str:
    # If behind proxy, ensure your proxy sets X-Forwarded-For correctly.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _rate_limit(request: Request, limiter: TokenBucketLimiter):
    ip = _client_ip(request)
    ok, retry = limiter.allow(ip)
    if not ok:
        raise HTTPException(status_code=429, detail="Too Many Requests", headers={"Retry-After": str(int(retry) + 1)})

APP_CANCEL = "luna://paypal/cancel"

print("ALLOWED_ORIGINS:", ALLOWED_ORIGINS)
print("ALLOWED_HOSTS:", ALLOWED_HOSTS)

async def verificar_token(
    token: str,
    db: AsyncSession
):

    try:

        token_data = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = token_data["user_id"]

        usuario_actual = (
            await db.execute(
                select(User).where(
                    User.id == user_id,
                    User.activo == True
                )
            )
        ).scalar_one_or_none()

        if not usuario_actual:

            raise HTTPException(
                status_code=401,
                detail="Usuario inválido"
            )

        return usuario_actual

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Token inválido o expirado"
        )
# =========================
# MODELOS
# =========================
class ActivateRequest(BaseModel):
    licenseKey: str = Field(..., min_length=5)
    deviceId: str = Field(..., min_length=16)

class ActivateResponse(BaseModel):
    accessToken: str
    refreshToken: str
    token: str

class RefreshRequest(BaseModel):
    refreshToken: str = Field(..., min_length=10)
    deviceId: str = Field(..., min_length=16)

class RefreshResponse(BaseModel):
    accessToken: str
    refreshToken: str

class ValidateRequest(BaseModel):
    deviceId: str = Field(..., min_length=16)

@app.get("/health")
async def health():
    print("ENTRO A HEALTH")
    return {"ok": True}



# =========================
# INTERNAL AUTH (optional)
# =========================
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "").strip()

def require_internal_key(x_internal_key: str = Header(default="")):
    """If INTERNAL_API_KEY is set, require X-Internal-Key header."""
    if INTERNAL_API_KEY:
        if not x_internal_key or x_internal_key != INTERNAL_API_KEY:
            raise HTTPException(status_code=403, detail="Forbidden")

# =========================
# HELPERS
# =========================
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def issue_access_token(licenseKey: str, deviceId: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "licenseKey": licenseKey,
        "deviceId": deviceId,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_MINUTES)).timestamp()),
        "typ": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def issue_refresh_token() -> str:
    return secrets.token_urlsafe(48)

async def ensure_license_ok(db: AsyncSession, licenseKey: str, deviceId: str) -> str:
    """
    Valida licencia en Postgres, aplica límite de dispositivos y registra/actualiza el device.
    Retorna license_id (UUID como str).
    """
    # 1) Buscar licencia
    res = await db.execute(
        text("""
            SELECT id, status, max_devices, expires_at
            FROM licenses
            WHERE license_key = :k
            LIMIT 1
        """),
        {"k": licenseKey},
    )
    lic = res.mappings().first()

    if not lic:
        raise HTTPException(status_code=401, detail="Licencia inválida")

    if lic["status"] != "active":
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    # 1.1) Verificar expiración (UTC)
    exp_at = lic["expires_at"]
    if exp_at is not None:
        # Si viene naive, asumimos UTC (mejor que comparar naive con aware)
        if getattr(exp_at, "tzinfo", None) is None:
            exp_at = exp_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) >= exp_at:
            raise HTTPException(status_code=403, detail="Licencia expirada")

    license_id = lic["id"]
    max_devices = int(lic["max_devices"] or 1)

    # 2) Ver si el device existe
    res = await db.execute(
        text("""
            SELECT id, revoked
            FROM license_devices
            WHERE license_id = :lid AND device_id = :did
            LIMIT 1
        """),
        {"lid": license_id, "did": deviceId},
    )
    dev = res.mappings().first()

    if dev:
        if bool(dev["revoked"]):
            raise HTTPException(status_code=403, detail="Dispositivo revocado")

        await db.execute(
            text("""
                UPDATE license_devices
                SET last_seen_at = NOW()
                WHERE license_id = :lid AND device_id = :did
            """),
            {"lid": license_id, "did": deviceId},
        )
        await db.commit()
        return str(license_id)

    # 3) Contar devices activos
    res = await db.execute(
        text("""
            SELECT COUNT(*) AS c
            FROM license_devices
            WHERE license_id = :lid AND revoked = FALSE
        """),
        {"lid": license_id},
    )
    row = res.mappings().first()
    count_active = int(row["c"] or 0)

    if count_active >= max_devices:
        raise HTTPException(status_code=409, detail="Límite de dispositivos alcanzado")

    # 4) Insertar device nuevo
    device_row_id = str(uuid.uuid4())

    await db.execute(
        text("""
            INSERT INTO license_devices
              (id, license_id, device_id, first_activated_at, last_seen_at, revoked)
            VALUES
              (:id, :lid, :did, NOW(), NOW(), FALSE)
        """),
        {"id": device_row_id, "lid": license_id, "did": deviceId},
    )
    await db.commit()
    return str(license_id)

async def create_refresh_session(db: AsyncSession, license_id: str, deviceId: str) -> str:
    """
    Crea una sesión de refresh en license_sessions.
    FIX CLAVE: interval con multiplicación, no concatenación de strings.
    """
    refresh = issue_refresh_token()
    r_hash = sha256_hex(refresh)
    sess_id = str(uuid.uuid4())

    await db.execute(
        text("""
            INSERT INTO license_sessions
              (id, license_id, device_id, refresh_token_hash, issued_at, expires_at, revoked)
            VALUES
              (:id, :lid, :did, :h, NOW(), NOW() + (:days * INTERVAL '1 day'), FALSE)
        """),
        {"id": sess_id, "lid": license_id, "did": deviceId, "h": r_hash, "days": REFRESH_DAYS},
    )
    await db.commit()
    return refresh

async def validate_refresh(db: AsyncSession, refreshToken: str, deviceId: str) -> str:
    r_hash = sha256_hex(refreshToken)

    res = await db.execute(
        text("""
            SELECT l.license_key, ls.device_id, ls.expires_at, ls.revoked
            FROM license_sessions ls
            JOIN licenses l ON l.id = ls.license_id
            WHERE ls.refresh_token_hash = :h
            LIMIT 1
        """),
        {"h": r_hash},
    )
    rec = res.mappings().first()

    if not rec:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

    if bool(rec["revoked"]) is True:
        raise HTTPException(status_code=401, detail="Refresh token revocado")

    exp_at = rec["expires_at"]  # ✅ SIEMPRE asignado aquí

    if exp_at is None:
        raise HTTPException(status_code=401, detail="Refresh token expirado")

    if exp_at.tzinfo is None:
        exp_at = exp_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) >= exp_at:
        raise HTTPException(status_code=401, detail="Refresh token expirado")

    if rec["device_id"] != deviceId:
        raise HTTPException(status_code=401, detail="Refresh token no pertenece a este dispositivo")

    return rec["license_key"]

# =========================
# ENDPOINTS
# =========================
@app.post("/activate", response_model=ActivateResponse)
async def activate(req: ActivateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _rate_limit(request, limiter_sensitive)
    logger.info("activate request")
    license_id = await ensure_license_ok(db, req.licenseKey, req.deviceId)
    access = issue_access_token(req.licenseKey, req.deviceId)
    refresh = await create_refresh_session(db, license_id, req.deviceId)
    logger.info("activate issued tokens")
    token = jwt.encode(
        {
            "exp": datetime.utcnow() + timedelta(days=5)
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )
    return {"accessToken": access, "refreshToken": refresh, "token": token}

@app.post("/refresh", response_model=RefreshResponse)
async def refresh(req: RefreshRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _rate_limit(request, limiter_sensitive)
    try:
        license_key = await validate_refresh(db, req.refreshToken, req.deviceId)
        await ensure_license_ok(db, license_key, req.deviceId)
        new_access = issue_access_token(license_key, req.deviceId)
        return {"accessToken": new_access, "refreshToken": req.refreshToken}
    except DBAPIError:
        # si quieres ver el error real en consola, puedes loguearlo antes de responder
        raise HTTPException(status_code=503, detail="DB no disponible, intenta de nuevo")

@app.post("/validate")
async def validate(
    req: ValidateRequest,
    authorization: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta Bearer token")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Access token inválido")

    if payload.get("deviceId") != req.deviceId:
        raise HTTPException(status_code=401, detail="Token no pertenece a este dispositivo")

    lic_key = payload.get("licenseKey")
    if not lic_key:
        raise HTTPException(status_code=401, detail="Token inválido")

    await ensure_license_ok(db, lic_key, req.deviceId)

    return {"ok": True}

# Get planes
@app.get("/plans/{plan_key}")
async def get_plan(
    plan_key: str,
    env: PaypalEnv = Query(PaypalEnv.sandbox, description="sandbox o live"),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(Planes)
        .where(
            Planes.plan_key == plan_key,
            Planes.env == env,
            Planes.is_active == True,
        )
        .limit(1)
    )
    

    result = await db.execute(stmt)
    plan = result.scalars().first()

    if not plan:
        raise HTTPException(status_code=404, detail="Plan no encontrado o inactivo")

    return {
        "plan_key": plan.plan_key,
        "env": plan.env.value if hasattr(plan.env, "value") else str(plan.env),
        "paypal_plan_id": plan.paypal_plan_id,
        "price": str(plan.price),      # Numeric -> string
        "currency": plan.currency,
        "name": plan.name,
        "id": plan.id,
    }
    
    # 
    
# --------- PAYPAL TOKEN ----------
async def get_access_token() -> str:
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Faltan credenciales PayPal")

    auth = base64.b64encode(
        f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()
    ).decode()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/oauth2/token",
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data="grant_type=client_credentials",
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.text)

    return r.json()["access_token"]

class CreateSubscriptionBody(BaseModel):
    plan_id: str
    user_id: str
    correo_user: str
    env: PaypalEnv = PaypalEnv.sandbox
    
from sqlalchemy import select, desc
from models import PaypalSubscription

@app.post("/paypal/create-subscription")
async def create_subscription(
    body: CreateSubscriptionBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    _rate_limit(request, limiter_sensitive)
    token = await get_access_token()

    payload = {
        "plan_id": body.plan_id,
        "custom_id": body.user_id,
        "application_context": {
            "brand_name": "LUNA",
            "user_action": "SUBSCRIBE_NOW",
            "return_url": PAYPAL_RETURN_URL,
            "cancel_url": PAYPAL_CANCEL_URL,
        },
    }
    
    logger.info("create-subscription for user_id=%s", body.user_id)

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )
        
        

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    data = r.json()
    approve_url = next((l["href"] for l in data.get("links", []) if l.get("rel") == "approve"), None)

    paypal_subscription_id = data.get("id")
    paypal_status = data.get("status") or "CREATED"

    env_value = body.env.value if hasattr(body.env, "value") else str(body.env)

    # ✅ Busca el registro mas reciente para (user_id, env, plan_id)
    q = await db.execute(
        select(PaypalSubscription)
        .where(
            PaypalSubscription.user_id == body.user_id,
            PaypalSubscription.env == env_value,
            PaypalSubscription.paypal_plan_id == body.plan_id,
        )
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    row = q.scalar_one_or_none()

    if row:
        # ✅ Actualiza el existente
        row.paypal_subscription_id = paypal_subscription_id
        row.status = paypal_status
        row.approve_url = approve_url
        row.raw = data
    else:
        # ✅ Inserta uno nuevo
        row = PaypalSubscription(
            env=env_value,
            user_id=body.user_id,
            paypal_plan_id=body.plan_id,
            paypal_subscription_id=paypal_subscription_id,
            status=paypal_status,
            approve_url=approve_url,
            subscriber_email=body.correo_user,
            raw=data,
        )
        db.add(row)

    await db.commit()

    return {
        "subscription_id": paypal_subscription_id,
        "status": paypal_status,
        "approve_url": approve_url,
    }

@app.get("/paypal/subscription-status")
async def paypal_subscription_status(subscription_id: str):
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    data = r.json()
    return {
        "id": data.get("id"),
        "status": data.get("status"),  # ACTIVE / APPROVAL_PENDING / CANCELLED...
    }

def generate_license_key(prefix: str = "LUNA") -> str:
    chars = string.ascii_uppercase + string.digits  # A-Z 0-9
    
    def block(n=4):
        return "".join(secrets.choice(chars) for _ in range(n))
    
    return f"{prefix}-{block()}-{block()}-{block()}"
""" @app.get("/paypal/return")
async def paypal_return(subscription_id: str, db: AsyncSession = Depends(get_db)):
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"}
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail=r.json())

    data = r.json()
    status = data.get("status")  # ACTIVE, APPROVAL_PENDING, CANCELLED, etc.
    user_id = data.get("custom_id")  # el que mandaste en create-subscription como custom_id

    # 1) Buscar suscripción
    q = await db.execute(
        select(PaypalSubscription)
        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    row = q.scalar_one_or_none()

    # 2) Crear o actualizar
    if not row:
        row = PaypalSubscription(
            env=data.get("environment") or "sandbox",
            user_id=user_id,
            paypal_plan_id=data.get("plan_id"),
            paypal_subscription_id=subscription_id,
            status=status,
            approve_url=None,
            raw=data,
            # license_id=None  # si existe el campo
        )
        db.add(row)
    else:
        row.status = status
        row.raw = data

    # 3) ✅ Si ya está ACTIVE, crear licencia (una sola vez)
    created_license = None
    if status == "ACTIVE":
        # Idempotencia: si ya tiene licencia asociada, no crear otra
        if getattr(row, "license_id", None) is None:
            # generar key y asegurar unicidad
            # (por si colisiona con UNIQUE, reintenta)
            for _ in range(5):
                key = generate_license_key()
                lic = License(
                    user_id=row.user_id,
                    license_key=key,
                    status="active",
                    max_devices=1,
                    notes=f"Created from PayPal subscription {subscription_id}",
                )
                db.add(lic)
                try:
                    await db.flush()  # obtiene lic.id y valida UNIQUE(license_key) sin commit aún
                    created_license = lic
                    break
                except Exception:
                    # posible colisión unique (muy raro) u otro error => reintenta
                    await db.rollback()
                    # reatacha row porque rollback la saca del estado pending en algunos casos
                    # (alternativa: manejar IntegrityError específicamente)
                    q2 = await db.execute(
                        select(PaypalSubscription)
                        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
                        .order_by(desc(PaypalSubscription.created_at))
                        .limit(1)
                    )
                    row = q2.scalar_one()

            if created_license:
                row.license_id = created_license.id  # requiere columna license_id

    await db.commit()

    return {
        "ok": True,
        "subscription_id": subscription_id,
        "status": status,
        "license": {
            "id": str(created_license.id),
            "license_key": created_license.license_key,
        } if created_license else None
    }
     """
     
@app.get("/paypal/return")
def paypal_return():
    return {"ok": True, "status": "ACTIVE"}

from sqlalchemy import select, desc
from fastapi import Depends, HTTPException

@app.get("/paypal/restore")
async def restore(user_id: str, db: AsyncSession = Depends(get_db)):
    q = await db.execute(
        select(PaypalSubscription)
        .where(
            PaypalSubscription.user_id == user_id,
            PaypalSubscription.status == "ACTIVE"
        )
        .order_by(desc(PaypalSubscription.created_at))
        .limit(1)
    )
    sub = q.scalar_one_or_none()
    if not sub:
        return {"ok": False, "msg": "No hay suscripción activa"}

    # ✅ Buscar licencia por subscription_id (guardado en licenses.user_id)
    q2 = await db.execute(
        select(License)
        .where(License.user_id == sub.paypal_subscription_id)
        .order_by(desc(License.created_at))
        .limit(1)
    )
    lic = q2.scalar_one_or_none()

    return {
        "ok": True,
        "subscription_id": sub.paypal_subscription_id,
        "status": sub.status,
        "license_key": lic.license_key if lic else None,
    }



""" @app.get("/paypal/return")
def paypal_return(subscription_id: str | None = None):
    return RedirectResponse(
        url=f"luna://paypal/success?sub={subscription_id or ''}"
    ) """

@app.get("/paypal/cancel")
def paypal_cancel():
    return {"ok": True, "status": "CANCELLED"}

async def verify_paypal_webhook(request: Request, body: dict, token: str):
    # ✅ DEV BYPASS: permite Invoke-RestMethod sin headers
    if not VERIFY_PAYPAL_WEBHOOKS:
        return True

    # Headers que PayPal SIEMPRE manda para verificar
    transmission_id = request.headers.get("paypal-transmission-id")
    transmission_time = request.headers.get("paypal-transmission-time")
    cert_url = request.headers.get("paypal-cert-url")
    auth_algo = request.headers.get("paypal-auth-algo")
    transmission_sig = request.headers.get("paypal-transmission-sig")

    if not PAYPAL_WEBHOOK_ID:
        raise HTTPException(status_code=500, detail="PAYPAL_WEBHOOK_ID is not set")

    if not all([transmission_id, transmission_time, cert_url, auth_algo, transmission_sig]):
        raise HTTPException(
            status_code=400,
            detail="Missing PayPal verification headers",
        )

    payload = {
        "auth_algo": auth_algo,
        "cert_url": cert_url,
        "transmission_id": transmission_id,
        "transmission_sig": transmission_sig,
        "transmission_time": transmission_time,
        "webhook_id": PAYPAL_WEBHOOK_ID,
        "webhook_event": body,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=400, detail={"verify_error": r.json()})

    verification_status = r.json().get("verification_status")
    if verification_status != "SUCCESS":
        raise HTTPException(status_code=400, detail={"verification_status": verification_status})

    return True

def _extract_subscription_id(event_type: str | None, body: dict) -> str | None:
    resource = body.get("resource") or {}

    subscription_id = None

    # Eventos de suscripción "nativos" (BILLING.SUBSCRIPTION.*)
    if body.get("resource_type") == "subscription" or (event_type or "").startswith("BILLING.SUBSCRIPTION."):
        subscription_id = resource.get("id")

    # Eventos de pago/sale/capture
    if not subscription_id:
        subscription_id = resource.get("billing_agreement_id")

    return subscription_id


def _extract_resource_id(body: dict) -> str | None:
    resource = body.get("resource") or {}
    return (
        resource.get("id")
        or resource.get("billing_agreement_id")
        or resource.get("custom_id")
        or None
    )


async def _register_paypal_event(db: AsyncSession, *, env: PaypalEnv, body: dict) -> tuple[bool, int | None]:
    """
    Inserta el evento en paypal_webhook_events (idempotente).
    Retorna: (is_duplicate, event_row_id)
    """
    paypal_event_id = body.get("id")  # PayPal EVENT id (normalmente viene como "id")
    event_type = body.get("event_type") or "UNKNOWN"

    if not paypal_event_id:
        raise HTTPException(status_code=400, detail="Webhook PayPal sin body.id (paypal_event_id)")

    resource_id = _extract_resource_id(body)

    stmt = (
        insert(PaypalWebhookEvent)
        .values(
            env=env,
            paypal_event_id=paypal_event_id,
            event_type=event_type,
            resource_id=resource_id,
            payload=body,
            processing_status="received",
        )
        .on_conflict_do_nothing(index_elements=["env", "paypal_event_id"])
        .returning(PaypalWebhookEvent.id)
    )

    res = await db.execute(stmt)
    new_id = res.scalar_one_or_none()
    return (new_id is None), new_id


async def _mark_paypal_event(db: AsyncSession, *, event_row_id: int, status: str):
    await db.execute(
        update(PaypalWebhookEvent)
        .where(PaypalWebhookEvent.id == event_row_id)
        .values(
            processing_status=status,   # processed|failed
            processed_at=datetime.now(timezone.utc),
        )
    )


@app.post("/paypal/webhook")
async def paypal_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    _rate_limit(request, limiter_webhook)
    body = await request.json()

    # ✅ ENV (ajústalo a tu config real)
    # Si guardas env="sandbox" en PaypalSubscription, usa sandbox aquí.
    env = PaypalEnv.sandbox  # en producción: PaypalEnv.live

    # ✅ 0) REGISTRAR EVENTO (SIEMPRE PRIMERO) + idempotencia
    try:
        is_dup, event_row_id = await _register_paypal_event(db, env=env, body=body)
        await db.commit()  # commit SOLO del log
    except Exception as e:
        await db.rollback()
        # Para no provocar reintentos infinitos de PayPal, responde 200
        return {"ok": True, "msg": f"No se pudo registrar el evento: {str(e)}"}

    # Si es duplicado, no reproceses
    if is_dup:
        return {"ok": True, "duplicate": True}

    try:
        # 1) Verificar firma (solo si está activado)
        if VERIFY_PAYPAL_WEBHOOKS:
            token = await get_access_token()
            await verify_paypal_webhook(request, body, token)
        # else: DEV ONLY

        # 2) Procesar evento
        event_type = body.get("event_type")
        resource = body.get("resource", {}) or {}

        # ✅ subscription_id robusto
        subscription_id = _extract_subscription_id(event_type, body)

        # status
        status = resource.get("status")

        # user_id (custom_id) puede venir o no según evento
        user_id = resource.get("custom_id")

        # 3) DB update
        if not subscription_id:
            # No puedo asociar nada, pero el evento ya quedó logueado
            await _mark_paypal_event(db, event_row_id=event_row_id, status="processed")
            await db.commit()
            return {"ok": True, "msg": "No subscription_id found in webhook"}

        q = await db.execute(
            select(PaypalSubscription)
            .where(PaypalSubscription.paypal_subscription_id == subscription_id)
            .order_by(desc(PaypalSubscription.created_at))
            .limit(1)
        )
        row = q.scalar_one_or_none()

        if not row:
            # crear
            row = PaypalSubscription(
                env="sandbox",
                user_id=user_id or "UNKNOWN",
                paypal_plan_id=resource.get("plan_id"),
                paypal_subscription_id=subscription_id,
                status=status or "UNKNOWN",
                approve_url=None,
                raw=body,
            )
            db.add(row)
            await db.flush()  # asegura row.id si lo necesitas
        else:
            row.status = status or row.status
            row.raw = body

        # ✅ ACTIVAR (cuando se activa la suscripción)
        is_active = (event_type == "BILLING.SUBSCRIPTION.ACTIVATED" or status == "ACTIVE")

        if is_active and getattr(row, "license_id", None) is None:
            key = None
            lic = None

            for _ in range(5):
                key = generate_license_key()

                # ⚠️ Si tu diseño REAL es que License.user_id sea el machine_id:
                # usa: user_id=(row.user_id or user_id or "UNKNOWN")
                # Si tu diseño es usar subscription_id como "user_id" de licencia, deja esto:
                lic = License(
                    user_id=subscription_id,
                    license_key=key,
                    status="active",
                    max_devices=2,
                    notes=f"Created from PayPal webhook {subscription_id}",
                )
                db.add(lic)

                try:
                    await db.flush()
                    row.license_id = lic.id
                    break
                except Exception:
                    await db.rollback()

                    # Re-obtener la suscripción para evitar estado inválido
                    q2 = await db.execute(
                        select(PaypalSubscription)
                        .where(PaypalSubscription.paypal_subscription_id == subscription_id)
                        .order_by(desc(PaypalSubscription.created_at))
                        .limit(1)
                    )
                    row = q2.scalar_one()

            # Enviar correo si hay email guardado y key creada
            if row and getattr(row, "subscriber_email", None) and key:
                enviar_correo(
                    row.subscriber_email,
                    key,
                    max_devices="2",
                    plan="LUNA PREMIUM",
                    renovacion="21/2/2026",
                    subscription_id=subscription_id,
                )
            else:
                print("Esta suscripción no tiene correo guardado aún")

        # ✅ Pagos mensuales: sale/capture completed
        is_payment_ok = event_type in ("PAYMENT.SALE.COMPLETED", "PAYMENT.CAPTURE.COMPLETED")

        if is_payment_ok:
            qlic = await db.execute(
                select(License)
                .where(License.user_id == subscription_id)
                .limit(1)
            )
            lic = qlic.scalar_one_or_none()

            if not lic:
                for _ in range(5):
                    key = generate_license_key()
                    lic = License(
                        user_id=subscription_id,
                        license_key=key,
                        status="active",
                        max_devices=2,
                        notes=f"Activated by payment webhook {subscription_id}",
                    )
                    db.add(lic)
                    try:
                        await db.flush()
                        break
                    except Exception:
                        await db.rollback()
            else:
                if lic.status != "active":
                    lic.status = "active"
                    lic.paypal_status = "ACTIVE"
                    lic.cancel_requested = False

        # ✅ REVOCAR
        lic = None

        if event_type in (
            "BILLING.SUBSCRIPTION.CANCELLED",
            "BILLING.SUBSCRIPTION.SUSPENDED",
            "BILLING.SUBSCRIPTION.EXPIRED",
        ):
            # buscar licencia (si existe)
            qlic = await db.execute(
                select(License)
                .where(License.user_id == subscription_id)
                .order_by(desc(License.created_at))
                .limit(1)
            )
            lic = qlic.scalar_one_or_none()

            # ✅ SIEMPRE marcar intención de cancelación
            if lic:
                lic.cancel_requested = True

            # ✅ Si es CANCELLED: NO tocar status local ni revocar (PayPal puede seguir ACTIVE hasta fin de periodo)
            if event_type == "BILLING.SUBSCRIPTION.CANCELLED":
                pass

            else:
                # SUSPENDED / EXPIRED sí deben reflejarse localmente
                map_status = {
                    "BILLING.SUBSCRIPTION.SUSPENDED": "SUSPENDED",
                    "BILLING.SUBSCRIPTION.EXPIRED": "EXPIRED",
                }
                row.status = map_status.get(event_type, row.status)

                if lic:
                    lic.status = "revoked"
                    lic.paypal_status = row.status
        # ✅ Marcar evento como processed + commit final
        await _mark_paypal_event(db, event_row_id=event_row_id, status="processed")
        await db.commit()
        return {"ok": True}

    except Exception as e:
        await db.rollback()

        # ✅ Marcar evento como failed (commit separado)
        try:
            await _mark_paypal_event(db, event_row_id=event_row_id, status="failed")
            await db.commit()
        except Exception:
            await db.rollback()

        # Responder 200 para que PayPal no reintente infinito.
        return {"ok": True, "msg": "Evento registrado pero falló el procesamiento", "error": str(e)}



# 
class CreateProductBody(BaseModel):
    name: str = "LUNA Premium"
    description: str = "Suscripción mensual a LUNA"
    

@app.post("/paypal/create-product")
async def create_product(
    body: CreateProductBody,
    _=Depends(require_internal_key),
):
    token = await get_access_token()

    payload = {
        "name": body.name,
        "type": "SERVICE",
        "category": "SOFTWARE",
        "description": body.description,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/catalogs/products",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
        )

    if r.status_code >= 400:
        try:
            detail = r.json()
        except Exception:
            detail = {"raw": r.text}
        raise HTTPException(status_code=r.status_code, detail=detail)

    return r.json()

class CreatePlanBody(BaseModel):
    product_id: str
    price: str = "9.99"
    currency: str = "USD"

@app.post("/paypal/create-plan")
async def create_plan(
    body: CreatePlanBody,
    _=Depends(require_internal_key),
):
    token = await get_access_token()

    payload = {
        "product_id": body.product_id,
        "name": "LUNA Mensual",
        "billing_cycles": [
            {
                "frequency": {"interval_unit": "MONTH", "interval_count": 1},
                "tenure_type": "REGULAR",
                "sequence": 1,
                "total_cycles": 0,  # 0 = ilimitado
                "pricing_scheme": {
                    "fixed_price": {"value": str(body.price), "currency_code": body.currency}
                },
            }
        ],
        "payment_preferences": {
            "auto_bill_outstanding": True,
            "setup_fee_failure_action": "CANCEL",
            "payment_failure_threshold": 3,
        },
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{PAYPAL_BASE_URL}/v1/billing/plans",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
        )

    if r.status_code >= 400:
        # Manejo robusto del error
        try:
            detail = r.json()
        except Exception:
            detail = {"raw": r.text}
        raise HTTPException(status_code=r.status_code, detail=detail)

    return r.json()
# Extraer datos licencias desde paypal

@app.get("/license/extract")
async def extract_license_info(
    _=Depends(require_internal_key),

    license_key: str = Query(..., min_length=5),
    db: AsyncSession = Depends(get_db),
):
    # 1) Buscar licencia por key
    q = await db.execute(select(License).where(License.license_key == license_key))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    # 2) Tomar subscription_id desde la BD (licenses.user_id)
    subscription_id = (lic.user_id or "").strip()
    if not subscription_id:
        raise HTTPException(
            status_code=400,
            detail="Esta licencia no tiene subscription_id en licenses.user_id",
        )

    # 3) Consultar PayPal
    token = await get_access_token()
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail={"paypal_error": r.json()})

    data = r.json()

    # 4) Extraer info útil
    paypal_status = data.get("status")  # ACTIVE, CANCELLED, SUSPENDED, etc.

    billing_info = data.get("billing_info") or {}
    last_payment = billing_info.get("last_payment") or {}
    last_payment_time = last_payment.get("time")
    last_payment_amount = (last_payment.get("amount") or {}).get("value")
    last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")
    next_billing_time = billing_info.get("next_billing_time")

    # 5) Sincronizar estado local
    if paypal_status != "ACTIVE":
        lic.status = "revoked"
    else:
        lic.status = "active"

    await db.commit()

    return {
        "ok": True,
        "license": {
            "license_key": lic.license_key,
            "status_local": lic.status,
            "subscription_id": subscription_id,
        },
        "paypal": {
            "status": paypal_status,
            "last_payment_time": last_payment_time,
            "last_payment_amount": last_payment_amount,
            "last_payment_currency": last_payment_currency,
            "next_billing_time": next_billing_time,
        },
    }
 
VERIFY_TTL_HOURS = 6
PAYPAL_FAIL_GRACE_HOURS = 24
CANCEL_REFRESH_GRACE_MINUTES = 5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def safe_upper(v: str | None) -> str:
    return (v or "").strip().upper()

def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def is_dt(v) -> bool:
    return isinstance(v, datetime)

def iso_or_none(v) -> str | None:
    return v.isoformat() if is_dt(v) else None

def get_attr(obj, name: str, default=None):
    return getattr(obj, name, default)

def set_attr_if_exists(obj, name: str, value):
    if hasattr(obj, name):
        setattr(obj, name, value)

def is_stale(last_sync_at: datetime | None, ttl_hours: float) -> bool:
    if not is_dt(last_sync_at):
        return True
    return (utcnow() - last_sync_at).total_seconds() > ttl_hours * 3600

def can_trust_cache(last_sync_at: datetime | None, grace_hours: float) -> bool:
    if not is_dt(last_sync_at):
        return False
    return (utcnow() - last_sync_at).total_seconds() <= grace_hours * 3600

def compute_paid_through_monthly(last_payment_time: datetime | None) -> datetime | None:
    if not is_dt(last_payment_time):
        return None
    return last_payment_time + relativedelta(months=1)

def compute_premium_window(
    paypal_status: str,
    last_payment_time: datetime | None,
    next_billing_time: datetime | None,
) -> tuple[bool, datetime | None]:
    """
    premium = now < paid_through
    paid_through = next_billing_time OR last_payment_time + 1 mes
    """
    now = utcnow()
    status = safe_upper(paypal_status)

    paid_through = next_billing_time if is_dt(next_billing_time) else None
    if not paid_through:
        paid_through = compute_paid_through_monthly(last_payment_time)

    if not paid_through:
        return False, None

    if status == "EXPIRED":
        return False, paid_through

    return now < paid_through, paid_through

CANCEL_REFRESH_WINDOW_HOURS = 24
CANCEL_TTL_MINUTES = 15

def refresh_due_to_cancel_requested(lic) -> bool:
    if not bool(get_attr(lic, "cancel_requested", False)):
        return False
    at = get_attr(lic, "cancel_requested_at", None)
    if not at:
        return True  # no sabemos cuándo, refresca siempre
    return utcnow() - at < timedelta(hours=CANCEL_REFRESH_WINDOW_HOURS)

def compute_paid_through_local(lic) -> datetime | None:
    """
    Calcula paid_through aunque no tengas columna:
    - si existe lic.paid_through úsalo
    - si no, usa last_payment_time + 1 mes
    """
    pt = get_attr(lic, "paid_through", None)
    if is_dt(pt):
        return pt

    lpt = get_attr(lic, "last_payment_time", None)
    if is_dt(lpt):
        return compute_paid_through_monthly(lpt)

    return None

def build_response(
    lic,
    subscription_id: str,
    premium: bool,
    source: str,
    paypal_status_real: str | None = None,   # lo que PayPal dijo ahora/último refresh
    paid_through: datetime | None = None,
    warning: str | None = None,
):
    # cached status (lo que tengas guardado)
    paypal_status_cached = get_attr(lic, "paypal_status", None)

    # asegura paid_through aunque sea cache
    paid_through_final = paid_through if is_dt(paid_through) else compute_paid_through_local(lic)

    return {
        "ok": True,
        "premium": premium,
        "source": source,
        **({"warning": warning} if warning else {}),
        "license": {
            "license_key": lic.license_key,
            "status_local": get_attr(lic, "status", None),
            "subscription_id": subscription_id,
            "last_sync_at": iso_or_none(get_attr(lic, "last_sync_at", None)),
            "cancel_requested": bool(get_attr(lic, "cancel_requested", False)),
            "paid_through": iso_or_none(paid_through_final),
        },
        "paypal": {
            # ✅ NO confundir más:
            "status_real": paypal_status_real,     # puede ser None en CACHE
            "status_cached": paypal_status_cached, # lo que está en DB
            # si quieres un solo "status" para el frontend:
            # - en refresh: usa real
            # - en cache: usa cached
            "status": paypal_status_real if paypal_status_real is not None else paypal_status_cached,

            "last_payment_time": iso_or_none(get_attr(lic, "last_payment_time", None)),
            "last_payment_amount": str(get_attr(lic, "last_payment_amount", None))
                if get_attr(lic, "last_payment_amount", None) is not None else None,
            "last_payment_currency": get_attr(lic, "last_payment_currency", None),
            "next_billing_time": iso_or_none(get_attr(lic, "next_billing_time", None)),
        },
    }


def compute_premium_from_local(lic) -> bool:
    """
    Decide si la licencia es premium SOLO con datos locales.
    No llama a PayPal.
    """
    # Si tienes status local
    status = getattr(lic, "status", None)
    if status == "active":
        return True

    # Fallback por fecha (si existe paid_through)
    paid_through = getattr(lic, "paid_through", None)
    if isinstance(paid_through, datetime):
        return utcnow() < paid_through

    # Último fallback: no premium
    return False


async def refresh_from_paypal(subscription_id: str) -> dict:
    """
    Devuelve el JSON de PayPal para una suscripción.
    """
    token = await get_access_token()

    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        r.raise_for_status()
        return r.json()
    
def mark_suspicious(lic, reason: str):
    """
    Marca la licencia como sospechosa y corta el premium.
    """
    if hasattr(lic, "suspicious"):
        lic.suspicious = True

    if hasattr(lic, "suspicious_reason"):
        lic.suspicious_reason = reason[:255]

    if hasattr(lic, "suspicious_at"):
        lic.suspicious_at = utcnow()

    # 🔒 Corte inmediato local
    if hasattr(lic, "status"):
        lic.status = "revoked"
    
@app.get("/license/verify")
async def verify_license(
    _=Depends(require_internal_key),
    license_key: str = Query(..., min_length=5),
    force_refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    # 1) Buscar licencia
    q = await db.execute(select(License).where(License.license_key == license_key))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    
    if bool(get_attr(lic, "suspicious", False)):
        return build_response(
            lic=lic,
            subscription_id=get_attr(lic, "user_id", None),
            premium=False,
            source="SECURITY_BLOCK",
            paypal_status_real=None,
            paid_through=get_attr(lic, "paid_through", None),
            warning="LICENSE_MARKED_SUSPICIOUS",
        )

    # 2) subscription_id (nuevo campo primero, fallback al user_id antiguo)
    subscription_id = (
        (get_attr(lic, "paypal_subscription_id", None) or get_attr(lic, "user_id", None) or "")
        .strip()
    )

    if not subscription_id:
        return {
            "ok": True,
            "premium": False,
            "reason": "NO_SUBSCRIPTION_ID",
            "source": "NO_SUBSCRIPTION_ID",
            "license": {
                "license_key": get_attr(lic, "license_key", None),
                "status_local": get_attr(lic, "status", None),
                "subscription_id": None,
                "last_sync_at": iso_or_none(get_attr(lic, "last_sync_at", None)),
                "cancel_requested": bool(get_attr(lic, "cancel_requested", False)),
                "paid_through": iso_or_none(get_attr(lic, "paid_through", None)),
            },
            "paypal": None,
        }

    # 3) Decide si refrescar:
    #    - force_refresh=True => siempre PayPal
    #    - cancel_requested=True => PayPal cada 15 min
    #    - normal => PayPal por TTL VERIFY_TTL_HOURS
    last_sync_at = get_attr(lic, "last_sync_at", None)
    cancel_requested = bool(get_attr(lic, "cancel_requested", False))

    cancel_stale = is_stale(last_sync_at, CANCEL_TTL_MINUTES / 60)  # minutos -> horas
    normal_stale = is_stale(last_sync_at, VERIFY_TTL_HOURS)

    must_refresh = bool(force_refresh) or (cancel_requested and cancel_stale) or normal_stale

    # 4) CACHE si está fresco y no hay que refrescar
    if not must_refresh:
        premium_local = compute_premium_from_local(lic)
        return build_response(
            lic=lic,
            subscription_id=subscription_id,
            premium=premium_local,
            source="CACHE",
            paypal_status_real=None,  # cache: no consultamos PayPal
            paid_through=get_attr(lic, "paid_through", None),
        )

    # 5) PAYPAL REFRESH
    try:
        data = await refresh_from_paypal(subscription_id)
        paypal_status_real = safe_upper(data.get("status"))

        billing_info = data.get("billing_info") or {}
        last_payment = billing_info.get("last_payment") or {}

        last_payment_time = parse_iso(last_payment.get("time"))
        next_billing_time = parse_iso(billing_info.get("next_billing_time"))

        premium_final, paid_through = compute_premium_window(
            paypal_status=paypal_status_real,
            last_payment_time=last_payment_time,
            next_billing_time=next_billing_time,
        )
        
        if paid_through and paid_through > utcnow() + timedelta(days=45):
            mark_suspicious(
                lic,
                f"PAID_THROUGH_TOO_FAR paid_through={paid_through.isoformat()}"
            )
            premium_final = False

        # Guardar mínimos
        set_attr_if_exists(lic, "user_id", subscription_id)
        set_attr_if_exists(lic, "last_sync_at", utcnow())

        # Guardar billing SOLO si existen columnas
        set_attr_if_exists(lic, "last_payment_time", last_payment_time)
        set_attr_if_exists(lic, "last_payment_amount", (last_payment.get("amount") or {}).get("value"))
        set_attr_if_exists(lic, "last_payment_currency", (last_payment.get("amount") or {}).get("currency_code"))
        set_attr_if_exists(lic, "next_billing_time", next_billing_time)
        set_attr_if_exists(lic, "paid_through", paid_through)

        # ✅ CANCELLED pero aún pagado -> mantener premium, marcar cancel_requested, NO tocar paypal_status
        if paypal_status_real == "CANCELLED" and premium_final:
            set_attr_if_exists(lic, "cancel_requested", True)
            if hasattr(lic, "cancel_requested_at") and get_attr(lic, "cancel_requested_at", None) is None:
                set_attr_if_exists(lic, "cancel_requested_at", utcnow())
            # NO tocar paypal_status
        else:
            set_attr_if_exists(lic, "paypal_status", paypal_status_real)
            set_attr_if_exists(lic, "cancel_requested", paypal_status_real == "CANCELLED")
            if hasattr(lic, "cancel_requested_at"):
                set_attr_if_exists(
                    lic,
                    "cancel_requested_at",
                    utcnow() if paypal_status_real == "CANCELLED" else None
                )

        # estado local
        set_attr_if_exists(lic, "status", "active" if premium_final else "revoked")
        await db.execute(text("SET LOCAL app.verified_write = '1'"))
        await db.commit()
        await db.refresh(lic)

        return build_response(
            lic=lic,
            subscription_id=subscription_id,
            premium=premium_final,
            source="PAYPAL_REFRESH",
            paypal_status_real=paypal_status_real,
            paid_through=paid_through,
        )

    except Exception as e:
        if can_trust_cache(get_attr(lic, "last_sync_at", None), PAYPAL_FAIL_GRACE_HOURS):
            premium_local = compute_premium_from_local(lic)
            return build_response(
                lic=lic,
                subscription_id=subscription_id,
                premium=premium_local,
                source="CACHE_FALLBACK",
                paypal_status_real=None,
                paid_through=get_attr(lic, "paid_through", None),
                warning="PAYPAL_UNAVAILABLE_USING_CACHE",
            )

        raise HTTPException(
            status_code=503,
            detail={
                "msg": "PayPal no disponible y no hay cache confiable. Intenta de nuevo.",
                "error": str(e),
            },
        )

def enviar_correo(destinatario: str, key: str, max_devices: str, plan: str, renovacion: str, subscription_id: str):
    # Si quieres usar un link real, define esto arriba o pásalo como parámetro
    APP_OPEN_URL = "https://tu-dominio.com/abrir-luna"  # o luna://open si usas deep link

    HTML_CONTENT = f"""\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Licencia LUNA</title>
</head>
<body style="margin:0;padding:0;background:#c7cfe9;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#c7cfe9;padding:20px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#111a2e;border-radius:14px;border:1px solid #223053;">

          <tr>
            <td style="padding:24px;color:#ffffff;">
              <h1 style="margin:0;font-size:22px;letter-spacing:2px;">L U N A</h1>
              <p style="margin:4px 0 0;color:#a9b0c3;font-size:12px;">Licencia &amp; Suscripción</p>
            </td>
          </tr>

          <tr>
            <td style="padding:0 24px 24px;color:#ffffff;">
              <h2 style="font-size:20px;margin:0 0 8px;">¡Gracias por tu compra! 🎉</h2>
              <p style="color:#c7cce0;font-size:14px;line-height:1.6;">
                Tu licencia de <strong>LUNA</strong> ya está activa. Guarda este correo, contiene la información
                necesaria para usar tu app.
              </p>

              <div style="margin:20px 0;">
                <p style="margin:0 0 6px;color:#a9b0c3;font-size:12px;">Tu clave de licencia:</p>
                <div style="background:#0b1224;border:1px dashed #2a3a66;border-radius:10px;
                  padding:12px;font-family:Consolas,monospace;font-size:16px;">
                  {key}
                </div>
                <p style="margin:6px 0 0;color:#a9b0c3;font-size:12px;">
                  Máximo de dispositivos: <strong style="color:#fff;">{max_devices}</strong>
                </p>
              </div>

              <table width="100%" cellpadding="0" cellspacing="0" style="background:#0b1224;
                border:1px solid #223053;border-radius:10px;padding:12px;margin-top:10px;">
                <tr>
                  <td style="color:#a9b0c3;font-size:12px;">Plan</td>
                  <td align="right" style="color:#ffffff;font-size:12px;"><strong>{plan}</strong></td>
                </tr>
                <tr>
                  <td style="color:#a9b0c3;font-size:12px;">Estado</td>
                  <td align="right" style="color:#ffffff;font-size:12px;"><strong>ACTIVA</strong></td>
                </tr>
                <tr>
                  <td style="color:#a9b0c3;font-size:12px;">Próxima renovación</td>
                  <td align="right" style="color:#ffffff;font-size:12px;"><strong>{renovacion}</strong></td>
                </tr>
                <tr>
                  <td style="color:#a9b0c3;font-size:12px;">ID Suscripción</td>
                  <td align="right" style="color:#ffffff;font-size:12px;font-family:Consolas,monospace;">
                    {subscription_id}
                  </td>
                </tr>
              </table>

              <div style="margin-top:18px;color:#c7cce0;font-size:14px;line-height:1.6;">
                <strong style="color:#fff;">Cómo activar tu licencia:</strong>
                <ol style="margin:8px 0 0 18px;padding:0;">
                  <li>Abre la aplicación LUNA.</li>
                  <li>Pega tu clave.</li>
                  <li>Dale al botón de activar ahora.</li>
                </ol>
              </div>

              <div style="margin-top:18px;">
                <a href="{APP_OPEN_URL}" style="background:#6d5efc;color:#fff;
                  padding:12px 18px;border-radius:10px;font-size:14px;font-weight:bold;
                  text-decoration:none;display:inline-block;">
                  Abrir LUNA
                </a>
              </div>

              <p style="margin-top:16px;color:#a9b0c3;font-size:12px;line-height:1.6;">
                Si tienes algún problema, responde a este correo indicando tu <strong>License Key</strong>
                y tu <strong>ID de suscripción</strong>.
                No compartas tu clave públicamente.
              </p>

              <hr style="border:none;border-top:1px solid #223053;margin:18px 0;">

              <p style="color:#8f96ad;font-size:11px;">
                © 2026 LUNA. Todos los derechos reservados.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    # Validación antes de abrir SMTP (mejor)
    if not SMTP_USER or not SMTP_APP_PASSWORD:
        raise RuntimeError("SMTP_USER/SMTP_APP_PASSWORD no configurados")

    msg = EmailMessage()
    msg["Subject"] = "Licencia LUNA | Activación"
    msg["From"] = EMAIL_FROM or SMTP_USER
    msg["To"] = destinatario

    # Texto plano útil (no lo dejes vacío)
    msg.set_content(
        f"Tu licencia LUNA está activa.\n\n"
        f"Clave: {key}\n"
        f"Plan: {plan}\n"
        f"Máx. dispositivos: {max_devices}\n"
        f"Próxima renovación: {renovacion}\n"
        f"Suscripción: {subscription_id}\n"
    )
    msg.add_alternative(HTML_CONTENT, subtype="html")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SMTP_USER, SMTP_APP_PASSWORD)
            smtp.send_message(msg)
        print("Correo enviado con éxito a", destinatario)
        return True
    except Exception as e:
        print("Error al enviar correo:", e)
        return False
    
@app.get("/paypal/verify-subscription")
async def verify_subscription(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    # 1) Buscar última suscripción del usuario
    q = await db.execute(
        select(PaypalSubscription)
        .where(PaypalSubscription.user_id == user_id)
        .order_by(PaypalSubscription.created_at.desc())
        .limit(1)
    )
    sub = q.scalar_one_or_none()

    if not sub:
        return { "ok": False, "status": "NO_SUBSCRIPTION" }

    # 2) Consultar PayPal
    token = await get_access_token()

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{sub.paypal_subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    if r.status_code != 200:
        return { "ok": False, "status": "PAYPAL_ERROR" }

    data = r.json()
    paypal_status = data["status"]  # ACTIVE, CANCELLED, SUSPENDED...

    # 3) Buscar licencia usando subscription_id
    q = await db.execute(
        select(License)
        .where(License.user_id == sub.paypal_subscription_id)
        .limit(1)
    )
    license = q.scalar_one_or_none()

    if not license:
        return {
            "ok": False,
            "status": paypal_status,
            "msg": "LICENSE_NOT_FOUND"
        }

    return {
        "ok": paypal_status == "ACTIVE",
        "subscription_id": sub.paypal_subscription_id,
        "status": paypal_status,
        "license_key": license.license_key,
    }
    
# Verificar status del usuario

@app.get("/verify/user")
async def verify_user(
    _=Depends(require_internal_key),

    license_key: str = Query(..., min_length=5),
    force_refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    # 1) Buscar licencia
    q = await db.execute(select(License).where(License.license_key == license_key))
    lic = q.scalar_one_or_none()
    if not lic:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")

    # 2) Resolver subscription_id (nuevo campo primero, fallback al user_id antiguo)
    subscription_id = (getattr(lic, "paypal_subscription_id", None) or getattr(lic, "user_id", None) or "").strip()
    if not subscription_id:
        return {
            "ok": True,
            "premium": False,
            "reason": "NO_SUBSCRIPTION_ID",
            "license": {"license_key": lic.license_key, "status_local": lic.status},
            "paypal": None,
        }

    # 3) Decisión rápida desde BD
    premium_local = compute_premium_from_local(lic)

    # 4) Si está fresco y no pidieron refresh: devuelve directo
    if not force_refresh and not is_stale(getattr(lic, "last_sync_at", None), VERIFY_TTL_HOURS):
        return {
            "ok": True,
            "premium": premium_local,
            "source": "CACHE",
            "license": {
                "license_key": lic.license_key,
                "status_local": lic.status,
                "subscription_id": subscription_id,
                "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
            },
            "paypal": {
                "status": lic.paypal_status,
                "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                "last_payment_currency": lic.last_payment_currency,
                "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
            },
        }

    # 5) Refrescar con PayPal (si se puede)
    try:
        data = await refresh_from_paypal(subscription_id)

        paypal_status = (data.get("status") or "").upper()

        billing_info = data.get("billing_info") or {}
        last_payment = billing_info.get("last_payment") or {}

        # Guardar en BD
        lic.user_id = subscription_id
        lic.paypal_status = paypal_status
        lic.last_payment_time = parse_iso(last_payment.get("time"))
        lic.last_payment_amount = (last_payment.get("amount") or {}).get("value")
        lic.last_payment_currency = (last_payment.get("amount") or {}).get("currency_code")
        lic.next_billing_time = parse_iso(billing_info.get("next_billing_time"))
        lic.last_sync_at = utcnow()

        # Sincronizar estado local básico
        lic.status = "active" if paypal_status == "ACTIVE" else "revoked"

        await db.commit()
        await db.refresh(lic)

        premium_final = compute_premium_from_local(lic)

        return {
            "ok": True,
            "premium": premium_final,
            "source": "PAYPAL_REFRESH",
            "license": {
                "license_key": lic.license_key,
                "status_local": lic.status,
                "subscription_id": subscription_id,
                "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
            },
            "paypal": {
                "status": lic.paypal_status,
                "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                "last_payment_currency": lic.last_payment_currency,
                "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
            },
        }

    except Exception as e:
        # 6) Si PayPal falla: usar cache si es confiable (grace window)
        if can_trust_cache(getattr(lic, "last_sync_at", None), PAYPAL_FAIL_GRACE_HOURS):
            return {
                "ok": True,
                "premium": premium_local,
                "source": "CACHE_FALLBACK",
                "warning": "PAYPAL_UNAVAILABLE_USING_CACHE",
                "license": {
                    "license_key": lic.license_key,
                    "status_local": lic.status,
                    "subscription_id": subscription_id,
                    "last_sync_at": lic.last_sync_at.isoformat() if lic.last_sync_at else None,
                },
                "paypal": {
                    "status": lic.paypal_status,
                    "last_payment_time": lic.last_payment_time.isoformat() if lic.last_payment_time else None,
                    "last_payment_amount": str(lic.last_payment_amount) if lic.last_payment_amount is not None else None,
                    "last_payment_currency": lic.last_payment_currency,
                    "next_billing_time": lic.next_billing_time.isoformat() if lic.next_billing_time else None,
                },
            }

        # Si no hay cache confiable: bloquear (seguridad)
        raise HTTPException(
            status_code=503,
            detail={
                "msg": "PayPal no disponible y no hay cache confiable. Intenta de nuevo.",
                "error": str(e),
            },
        )
  
# Vinculación
from typing import List
from uuid import UUID

PRIORIDAD_SYNC = {
    "create_company": 1,
    "actualizar_empresa": 1,

    "crear_usuario": 2,
    "actualizar_usuario": 2,

    "crear_caja": 3,
    "actualizar_caja": 3,

    "asignar_caja": 4,

    "crear_movimiento_caja": 5,
    "actualizar_movimiento_caja": 5,
}


from datetime import datetime, timezone, timedelta

RD = timezone(timedelta(hours=-4))

def parse_datetime(value):

    if not value:
        return None

    dt = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    return dt.astimezone(RD)

@app.post("/sync/batch")
async def sync_batch(
    items: List[dict],
    authorization: str = Header(None),
    _=Depends(require_internal_key),
    db: AsyncSession = Depends(get_db),
):

    try:
        
        if not authorization:
            raise HTTPException(
                status_code=401,
                detail="Token requerido"
            )

        token = authorization.replace(
            "Bearer ",
            ""
        )

        # Solo verificar usuario si NO viene create_company
        hay_create_company = any(
            item.get("type") == "create_company"
            for item in items
        )

        if not hay_create_company:

            usuario_actual = await verificar_token(
                token,
                db
            )


        items_ordenados = sorted(
            items,
            key=lambda x: {
                "empresa": 1,
                "usuario": 2,
                "crear_caja": 3,
                "asignar_caja": 4,
                "crear_movimiento_caja": 5,
                "cerrar_caja": 6,
                "crear_producto": 6,
            }.get(x["type"], 999)
        )
        
        print("ITEMS RECIBIDOS:")
        for item in items_ordenados:
            print(item["type"])

        for item in items_ordenados:

            item_type = item.get("type")
            payload = item.get("payload")

            if item_type == "create_company":
                
                uuid = payload["uuid"]

                q = await db.execute(
                    select(Company).where(Company.uuid == uuid)
                )

                exists = q.scalar_one_or_none()

                if not exists:

                    company = Company(
                        uuid=payload["uuid"],
                        nombre=payload.get("nombre"),
                        rnc=payload.get("rnc"),
                        telefono=payload.get("telefono"),
                        direccion=payload.get("direccion"),
                        ncf=payload.get("ncf"),
                    )

                    db.add(company)
                    
            elif item_type == "actualizar_empresa":

                uuid = payload["uuid"]

                q = await db.execute(
                    select(Company).where(Company.uuid == uuid)
                )

                company = q.scalar_one_or_none()

                if company:

                    incoming_version = payload.get("version", 1)

                    # 🔥 conflicto simple (última escritura gana o puedes bloquear)
                    if incoming_version >= company.version:

                        company.nombre = payload.get("nombre")
                        company.telefono = payload.get("telefono")
                        company.rnc = payload.get("rnc")
                        company.direccion = payload.get("direccion")
                        company.ncf = payload.get("ncf")
                        company.facturas_electronicas = payload.get("facturas_electronicas")
                        company.uso_balanza = payload.get("uso_balanza")

                        company.version += 1
                        company.updated_at = datetime.utcnow()
                        
            elif item_type == "crear_usuario":

                user_uuid = UUID(payload["id"])

                q = await db.execute(
                    select(User).where(
                        User.id == user_uuid,
                        User.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                exists = q.scalar_one_or_none()
        
                
                print("RAW ITEM:", item)
                print("PAYLOAD TYPE:", type(item.get("payload")))

                if not exists:

                    user = User(
                        id=user_uuid,
                        empresa_uuid=payload.get("empresa_uuid"),
                        nombre=payload.get("nombre"),
                        usuario=payload.get("usuario"),
                        codigo=payload.get("codigo"),
                       
                        activo=payload.get("activo", True),
                        permitir_nube=payload.get("permitir_nube", False),
                    )

                    db.add(user)


            elif item_type == "actualizar_usuario":

                id = payload["id"]

                q = await db.execute(
                    select(User).where(User.id == id, User.empresa_uuid == payload.get("empresa_uuid"))
                )

                user = q.scalar_one_or_none()

                if user:

                    incoming_version = payload.get("version", 1)

                    if incoming_version >= user.version:

                        user.nombre = payload.get("nombre")
                        user.usuario = payload.get("usuario")
                     
                        user.activo = payload.get("activo")
                        user.permitir_nube = payload.get("permitir_nube")

                        user.version += 1
                        user.updated_at = datetime.now(timezone.utc)
                        
            elif item_type == "crear_caja":

                caja_uuid = UUID(payload["id"])
                
                print("RAW ITEM:", item)
                print("PAYLOAD TYPE:", type(item.get("payload")))

                q = await db.execute(
                    select(CajaConfig).where(
                        CajaConfig.id == caja_uuid,
                        CajaConfig.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                exists = q.scalar_one_or_none()

                if not exists:

                    caja = CajaConfig(
                        id=caja_uuid,
                        empresa_uuid=payload.get("empresa_uuid"),
                        nombre=payload.get("nombre"),
                        activa=payload.get("activa", True),

                        sync_status=payload.get("sync_status", "synced"),
                        version=payload.get("version", 1),

                        deleted_at=payload.get("deleted_at")
                    )

                    db.add(caja)
            
            elif item_type == "actualizar_caja":

                caja_id = UUID(payload["id"])
                

                q = await db.execute(
                    select(CajaConfig).where(
                        CajaConfig.id == caja_id,
                        CajaConfig.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                caja = q.scalar_one_or_none()

                if caja:

                    incoming_version = payload.get("version", 1)

                    if incoming_version > caja.version:

                        caja.nombre = payload.get("nombre")
                        caja.activa = payload.get("activa", True)

                        caja.sync_status = payload.get(
                            "sync_status",
                            "synced"
                        )

                        caja.deleted_at = payload.get(
                            "deleted_at"
                        )

                        caja.version = incoming_version

                        caja.updated_at = (
                            parse_datetime(
                                payload.get("updated_at")
                            )
                            if payload.get("updated_at")
                            else None
                        )

                        await db.commit()
                        await db.refresh(caja)
                        
            elif item_type == "crear_movimiento_caja":

                movimiento_id = UUID(payload["id"])

                q = await db.execute(
                    select(CajaMovimiento).where(
                        CajaMovimiento.id == movimiento_id,
                        CajaMovimiento.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                exists = q.scalar_one_or_none()

                if not exists:
                    


                    movimiento = CajaMovimiento(
                        id=movimiento_id,

                        empresa_uuid=payload.get("empresa_uuid"),

                        caja_id=UUID(payload["caja_id"]),

                        usuario_id=UUID(payload["usuario_id"])
                        if payload.get("usuario_id")
                        else None,

                        venta_id=payload.get("venta_id"),

                        tipo=payload.get("tipo"),

                        monto=Decimal(
                            str(payload.get("monto", 0))
                        ),

                        descripcion=payload.get("descripcion"),

                        solicitado_por=UUID(
                            payload["solicitado_por"]
                        )
                        if payload.get("solicitado_por")
                        else None,

                        autorizado_por=UUID(
                            payload["autorizado_por"]
                        )
                        if payload.get("autorizado_por")
                        else None,

                        requiere_autorizacion=bool(
                            payload.get(
                                "requiere_autorizacion",
                                False
                            )
                        ),

                        estado_autorizacion=payload.get(
                            "estado_autorizacion",
                            "no_requiere"
                        ),

                        fecha_autorizacion=parse_datetime(
                            payload.get("fecha_autorizacion")
                        )
                        if payload.get("fecha_autorizacion")
                        else None,

                        sync_status=payload.get(
                            "sync_status",
                            "synced"
                        )
                    )

                    """ print(
                        "MOVIMIENTO PAYLOAD:",
                        payload
                    ) """

                    db.add(movimiento)
                    
            elif item_type == "resolver_movimiento_caja":
                movimiento_id = UUID(payload["id"])

                q = await db.execute(
                    select(CajaMovimiento).where(
                        CajaMovimiento.id == movimiento_id,
                        CajaMovimiento.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                movimiento = q.scalar_one_or_none()

                if movimiento:

                    movimiento.estado_autorizacion = payload.get(
                        "estado_autorizacion",
                        movimiento.estado_autorizacion
                    )

                    movimiento.autorizado_por = (
                        UUID(payload["autorizado_por"])
                        if payload.get("autorizado_por")
                        else None
                    )

                    movimiento.fecha_autorizacion = (
                        parse_datetime(
                            payload.get("fecha_autorizacion")
                        )
                        if payload.get("fecha_autorizacion")
                        else None
                    )

                    movimiento.sync_status = payload.get(
                        "sync_status",
                        "synced"
                    )

                    movimiento.updated_at = datetime.utcnow()

                    print(
                        "MOVIMIENTO RESUELTO:",
                        movimiento.id,
                        movimiento.estado_autorizacion
                    )

            elif item_type == "actualizar_movimiento_caja":

                movimiento_id = UUID(payload["id"])

                q = await db.execute(
                    select(CajaMovimiento).where(
                        CajaMovimiento.id == movimiento_id,
                        CajaMovimiento.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                movimiento = q.scalar_one_or_none()

                if movimiento:

                    movimiento.tipo = payload.get("tipo")
                    movimiento.monto = payload.get("monto")
                    movimiento.descripcion = payload.get("descripcion")

                    movimiento.usuario_id = (
                        UUID(payload["usuario_id"])
                        if payload.get("usuario_id")
                        else None
                    )

                    movimiento.venta_id = payload.get("venta_id")

                    movimiento.autorizado_por = (
                        UUID(payload["autorizado_por"])
                        if payload.get("autorizado_por")
                        else None
                    )

                    movimiento.sync_status = payload.get(
                        "sync_status",
                        "synced"
                    )

                    movimiento.updated_at = datetime.utcnow()
            
            elif item_type == "asignar_caja":

                caja_id = UUID(payload["id"])

                q = await db.execute(
                    select(Caja).where(
                        Caja.id == caja_id,
                        Caja.empresa_uuid == payload.get("empresa_uuid")
                    )
                )

                exists = q.scalar_one_or_none()

                if not exists:

                    caja = Caja(
                        id=caja_id,

                        empresa_uuid=
                            payload.get("empresa_uuid"),

                        caja_config_id=
                            UUID(payload["caja_config_id"]),
                            
                        numero_sesion = int(payload.get("numero_sesion", 1)),

                        usuario_id=
                            UUID(payload["usuario_id"]),

                        monto_inicial=Decimal(
                            str(
                                payload.get(
                                    "monto_inicial",
                                    0
                                )
                            )
                        ),

                        observacion=
                            payload.get("observacion"),

                        estado=
                            payload.get(
                                "estado",
                                "abierta"
                            )
                    )

                    db.add(caja)

                    await db.flush()
                    
            elif item_type == "cerrar_caja":

                caja_id = UUID(payload["id"])

                q = await db.execute(
                    select(Caja).where(
                        Caja.id == caja_id,
                        Caja.empresa_uuid ==
                            payload["empresa_uuid"]
                    )
                )
                
                print(
                        "CERRAR CAJA:",
                        payload
                    )
              

                caja = q.scalar_one_or_none()

                if caja:

                    incoming_version = payload.get("version", 1)

                    if incoming_version >= caja.version:

                        caja.estado = "cerrada"

                        caja.fecha_cierre = (
                        parse_datetime(
                            payload.get("fecha_cierre")
                        )
                        if payload.get("fecha_cierre")
                        else None
                    )

                        caja.monto_contado = (
                            payload.get(
                                "monto_contado"
                            )
                        )

                        caja.diferencia = (
                            payload.get(
                                "diferencia"
                            )
                        )

                        caja.motivo_cierre = (
                            payload.get(
                                "motivo_cierre"
                            )
                        )

                        caja.tipo_cierre = (
                            payload.get(
                                "tipo_cierre"
                            )
                        )

                        caja.cerrada_por = (
                            payload.get(
                                "cerrada_por"
                            )
                        )

                        caja.version = (
                            incoming_version
                        )

                        caja.updated_at = (
                        parse_datetime(
                            payload.get("updated_at")
                        )
                        if payload.get("updated_at")
                        else None
                    )

                        await db.flush()
                        
            elif item_type == "eliminar_caja":

                caja_id = UUID(payload["id"])

                q = await db.execute(
                    select(CajaConfig).where(CajaConfig.id == caja_id)
                )

                caja = q.scalar_one_or_none()

                if caja:

                    caja.deleted_at = datetime.utcnow()
                    caja.sync_status = "synced"
                    caja.version += 1
                    
            elif item_type == "crear_unidad_medida":

                unidad_id = UUID(payload["id"])

                q = await db.execute(
                    select(UnidadMedida).where(
                        UnidadMedida.id == unidad_id
                    )
                )

                unidad = q.scalar_one_or_none()

                if not unidad:

                    unidad = UnidadMedida(
                        id=unidad_id,
                        empresa_uuid=payload["empresa_uuid"],
                        nombre=payload["nombre"],
                        plural=payload["plural"],
                        permitir_decimal=payload.get(
                            "permitir_decimal",
                            False
                        ),
                        version=payload.get(
                            "version",
                            1
                        ),
                        sync_status="synced",
                        created_at=(
                            parse_datetime(
                                payload["created_at"]
                            )
                            if payload.get("created_at")
                            else None
                        ),
                        updated_at=(
                            parse_datetime(
                                payload["updated_at"]
                            )
                            if payload.get("updated_at")
                            else None
                        )
                    )

                    db.add(unidad)

                    await db.flush()
               
                    
            elif item_type == "crear_producto":

                producto_id = UUID(payload["id"])

                q = await db.execute(
                    select(Producto).where(
                        Producto.id == producto_id,
                        Producto.empresa_uuid == payload["empresa_uuid"]
                    )
                )

                producto = q.scalar_one_or_none()

                if not producto:

                    producto = Producto(
                        id=producto_id,
                        empresa_uuid=payload["empresa_uuid"],
                        codigo_barras=payload.get("codigo_barras"),
                        codigo_balanza=payload.get("codigo_balanza"),
                        codigo_interno=payload["codigo_interno"],
                        es_balanza=payload.get("es_balanza", False),
                        nombre=payload["nombre"],
                        precio=payload.get("precio", 0),
                        costo=payload.get("costo", 0),
                        stock=payload.get("stock", 0),
                        stock_minimo=payload.get("stock_minimo", 0),
                        itbis=payload.get("itbis", 0),
                        unidad_id=UUID(payload["unidad_id"]),
                        activo=payload.get("activo", True),
                        version=payload.get("version", 1),
                        sync_status="synced",
                        created_at=(
                            parse_datetime(payload["created_at"])
                            if payload.get("created_at")
                            else None
                        ),
                        updated_at=(
                            parse_datetime(payload["updated_at"])
                            if payload.get("updated_at")
                            else None
                        )
                    )

                    db.add(producto)

                    await db.flush()
                    
                 
            

            """ elif item_type == "create_producto":

                q = await db.execute(
                    select(Product).where(
                        Product.uuid == payload["uuid"]
                    )
                )

                exists = q.scalar_one_or_none()

                if not exists:

                    product = Product(
                        uuid=payload["uuid"],
                        empresa_uuid=payload.get("empresa_uuid"),
                        nombre=payload.get("nombre"),
                        precio=payload.get("precio"),
                        stock=payload.get("stock"),
                        codigo_barra=payload.get("codigo_barra"),
                        categoria=payload.get("categoria"),
                    )

                    db.add(product) """

        await db.commit()

        return {
            "ok": True
        }

    except Exception as e:

        await db.rollback()
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.get("/sync/empresa/changes")
async def company_changes(
    authorization: str = Header(None),

    empresa_uuid: str | None = None,
    since: str | None = None,
    db: AsyncSession = Depends(get_db)
):

    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )

    
    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )

    query = select(Company).where(
        Company.uuid == empresa_uuid
    )

    if since:

        since_dt = parser.isoparse(since)

        since_dt = since_dt.replace(
            tzinfo=None
        )

        query = query.where(
            Company.updated_at > since_dt
        )

    q = await db.execute(query)

    company = q.scalar_one_or_none()

    if not company:
        return []

    return [
        {
            "uuid": company.uuid,
            "nombre": company.nombre,
            "telefono": company.telefono,
            "rnc": company.rnc,
            "direccion": company.direccion,
            "ncf": company.ncf,
            "uso_balanza": company.uso_balanza,
            "facturas_electronicas": company.facturas_electronicas,
            "version": company.version,
            "sync_status": company.sync_status,
            "updated_at":
                company.updated_at.isoformat()
                if company.updated_at
                else None
        }
    ]
    
@app.get("/sync/usuarios/changes")
async def users_changes(
    empresa_uuid: str,
    since: str | None = None,
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
):
    
    
    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )
    
    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )
    
    
    
    query = select(User).where(
        User.empresa_uuid == empresa_uuid
    )

    if since:

        since_dt = parser.isoparse(since)

        since_dt = since_dt.replace(tzinfo=None)

        query = query.where(
            User.updated_at > since_dt
        )

    q = await db.execute(query)

    users = q.scalars().all()

    print("USERS:", len(users))
    print(users)

    return [
        {
            "id": str(u.id),
            "empresa_uuid": u.empresa_uuid,
            "nombre": u.nombre,
            "usuario": u.usuario,


            "activo": u.activo,
            "permitir_nube": u.permitir_nube,

            "token": u.token,
            "codigo": u.codigo,

            "sync_status": u.sync_status,

            "deleted_at":
                u.deleted_at.isoformat()
                if u.deleted_at else None,

            "updated_at":
                u.updated_at.isoformat()
                if u.updated_at else None,

            "version": u.version,

            "created_at":
                u.created_at.isoformat()
                if u.created_at else None
        }
        for u in users
    ]
    
@app.get("/sync/cajas_config/changes")
async def cajas_config_changes(
    empresa_uuid: str,
    since: str | None = None,
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
):
    
    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )
    
    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )

    query = select(CajaConfig).where(
        CajaConfig.empresa_uuid == empresa_uuid
    )

    if since:
        since_dt = parser.isoparse(since)

        since_dt = since_dt.replace(tzinfo=None)
        
        query = query.where(CajaConfig.updated_at > since_dt)

    q = await db.execute(query)
    cajas = q.scalars().all()

    return [
        {
            "id": str(c.id),
            "empresa_uuid": c.empresa_uuid,
            "nombre": c.nombre,
            "activa": c.activa,
            "sync_status": c.sync_status,
            "deleted_at": c.deleted_at.isoformat() if c.deleted_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            "version": c.version,
            "created_at":
                c.created_at.isoformat()
                if c.created_at else None
        }
        for c in cajas
    ]
    
@app.get("/sync/cajas/changes")
async def cajas_changes(
    empresa_uuid: str,
    since: str | None = None,
    limit: int = 5000,
    offset: int = 0,
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
):

    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )

    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )

    query = select(Caja).where(
        Caja.empresa_uuid == empresa_uuid
    )

    if since:

        since_dt = parser.isoparse(since)

        if since_dt.tzinfo:
            since_dt = since_dt.replace(
                tzinfo=None
            )

        query = query.where(
            Caja.updated_at > since_dt
        )

    query = query.order_by(
        Caja.updated_at.asc()
    )

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)

    cajas = result.scalars().all()

    return {
        "items": [
            {
                "id": str(c.id),
                "empresa_uuid": c.empresa_uuid,
                "caja_config_id": str(c.caja_config_id),

                "numero_sesion":
                    int(c.numero_sesion)
                    if c.numero_sesion is not None
                    else None,

                "usuario_id": str(c.usuario_id),

                "monto_inicial":
                    float(c.monto_inicial or 0),

                "monto_contado":
                    float(c.monto_contado)
                    if c.monto_contado is not None
                    else None,

                "diferencia":
                    float(c.diferencia)
                    if c.diferencia is not None
                    else None,

                "observacion": c.observacion,
                "motivo_cierre": c.motivo_cierre,
                "tipo_cierre": c.tipo_cierre,

                "cerrada_por":
                    str(c.cerrada_por)
                    if c.cerrada_por
                    else None,

                "estado": c.estado,
                "sync_status": c.sync_status,
                "version": c.version,

                "fecha_apertura":
                    c.fecha_apertura.isoformat()
                    if c.fecha_apertura
                    else None,

                "fecha_cierre":
                    c.fecha_cierre.isoformat()
                    if c.fecha_cierre
                    else None,

                "updated_at":
                    c.updated_at.isoformat()
                    if c.updated_at
                    else None,

                "created_at":
                    c.created_at.isoformat()
                    if c.created_at
                    else None
            }
            for c in cajas
        ],
        "has_more": len(cajas) == limit
    } 

@app.get("/sync/caja_movimientos/changes")
async def caja_movimientos_changes(
    empresa_uuid: str,
    since: str | None = None,
    limit: int = 5000,
    offset: int = 0,
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
):

    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )

    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )

    query = select(CajaMovimiento).where(
        CajaMovimiento.empresa_uuid == empresa_uuid
    )

    if since:

        since_dt = parser.isoparse(since)

        if since_dt.tzinfo:
            since_dt = since_dt.replace(
                tzinfo=None
            )

        query = query.where(
            CajaMovimiento.updated_at > since_dt
        )

    query = query.order_by(
        CajaMovimiento.updated_at.asc()
    )

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)

    movimientos = result.scalars().all()

    return {
        "items": [
            {
                "id": str(m.id),
                "empresa_uuid": m.empresa_uuid,

                "caja_id":
                    str(m.caja_id)
                    if m.caja_id
                    else None,

                "usuario_id":
                    str(m.usuario_id)
                    if m.usuario_id
                    else None,

                "venta_id":
                    str(m.venta_id)
                    if m.venta_id
                    else None,

                "tipo": m.tipo,

                "monto":
                    float(m.monto or 0),

                "descripcion": m.descripcion,

                "solicitado_por":
                    str(m.solicitado_por)
                    if m.solicitado_por
                    else None,

                "autorizado_por":
                    str(m.autorizado_por)
                    if m.autorizado_por
                    else None,

                "requiere_autorizacion":
                    m.requiere_autorizacion,

                "estado_autorizacion":
                    m.estado_autorizacion,

                "fecha_autorizacion":
                    m.fecha_autorizacion.isoformat()
                    if m.fecha_autorizacion
                    else None,

                "sync_status": m.sync_status,

                "updated_at":
                    m.updated_at.isoformat()
                    if m.updated_at
                    else None,

                "created_at":
                    m.created_at.isoformat()
                    if m.created_at
                    else None
            }
            for m in movimientos
        ],
        "has_more": len(movimientos) == limit
    }

@app.get("/sync/productos/changes")
async def productos_changes(
    empresa_uuid: str,
    since: str | None = None,
    limit: int = 5000,
    offset: int = 0,
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
):

    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )

    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )

    query = select(Producto).where(
        Producto.empresa_uuid == empresa_uuid
    )

    if since:

        since_dt = parser.isoparse(since)

        if since_dt.tzinfo:
            since_dt = since_dt.replace(
                tzinfo=None
            )

        query = query.where(
            Producto.updated_at > since_dt
        )

    query = query.order_by(
        Producto.updated_at.asc()
    )

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)

    productos = result.scalars().all()

    return {
        "items": [
            {
                "id": str(p.id),
                "empresa_uuid": p.empresa_uuid,

                "codigo_barras":
                    p.codigo_barras,

                "codigo_balanza":
                    p.codigo_balanza,

                "codigo_interno":
                    p.codigo_interno,

                "es_balanza":
                    p.es_balanza,

                "nombre":
                    p.nombre,

                "precio":
                    float(p.precio or 0),

                "costo":
                    float(p.costo or 0),

                "stock":
                    float(p.stock or 0),

                "stock_minimo":
                    float(
                        p.stock_minimo or 0
                    ),

                "itbis":
                    float(p.itbis or 0),

                "unidad_id":
                    str(p.unidad_id),

                "activo":
                    p.activo,

                "sync_status":
                    p.sync_status,

                "version":
                    p.version,

                "updated_at":
                    p.updated_at.isoformat()
                    if p.updated_at
                    else None,

                "created_at":
                    p.created_at.isoformat()
                    if p.created_at
                    else None,

                "deleted_at":
                    p.deleted_at.isoformat()
                    if p.deleted_at
                    else None
            }
            for p in productos
        ],
        "has_more": len(productos) == limit
    }

@app.get("/sync/unidades_medida/changes")
async def unidades_medida_changes(
    empresa_uuid: str,
    since: str | None = None,
    limit: int = 5000,
    offset: int = 0,
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
):

    token = authorization.replace(
        "Bearer ",
        ""
    )

    usuario_actual = await verificar_token(
        token,
        db
    )

    if usuario_actual.empresa_uuid != empresa_uuid:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado"
        )

    query = select(UnidadMedida).where(
        UnidadMedida.empresa_uuid == empresa_uuid
    )

    if since:

        since_dt = parser.isoparse(since)

        if since_dt.tzinfo:
            since_dt = since_dt.replace(
                tzinfo=None
            )

        query = query.where(
            UnidadMedida.updated_at > since_dt
        )

    query = query.order_by(
        UnidadMedida.updated_at.asc()
    )

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)

    unidades = result.scalars().all()

    return {
        "items": [
            {
                "id": str(u.id),

                "empresa_uuid":
                    u.empresa_uuid,

                "nombre":
                    u.nombre,

                "plural":
                    u.plural,

                "permitir_decimal":
                    u.permitir_decimal,

                "sync_status":
                    u.sync_status,

                "version":
                    u.version,

                "updated_at":
                    u.updated_at.isoformat()
                    if u.updated_at
                    else None,

                "created_at":
                    u.created_at.isoformat()
                    if u.created_at
                    else None,

                "deleted_at":
                    u.deleted_at.isoformat()
                    if u.deleted_at
                    else None
            }
            for u in unidades
        ],
        "has_more": len(unidades) == limit
    }
@app.post("/registrar-users")
async def register_user(
    payload: dict,
    db: AsyncSession = Depends(get_db)
):
    try:

        nombre = str(
            payload.get("nombre", "")
        ).strip()

        usuario = str(
            payload.get("usuario", "")
        ).strip()

        contraseña = str(
            payload.get("contraseña", "")
        ).strip()

        empresa_uuid = str(
            payload.get(
                "empresa_uuid",
                ""
            )
        ).strip()

        if not empresa_uuid:
            raise HTTPException(
                status_code=400,
                detail="Empresa requerida"
            )
            
        empresa = await db.execute(
            select(Company).where(
                Company.uuid == empresa_uuid
            )
        )

        empresa_obj = (
            empresa.scalar_one_or_none()
        )

        if not empresa_obj:
            raise HTTPException(
                status_code=404,
                detail="La empresa no existe"
            )
    
        total_users = await db.execute(
            select(func.count(User.id))
            .where(
                User.empresa_uuid == empresa_uuid
            )
        )

        cantidad_usuarios = (
            total_users.scalar() or 0
        )

        print(
            f"USUARIOS EMPRESA {empresa_uuid}:",
            cantidad_usuarios
        )

        # Si ya existe al menos un usuario
        # exigir api_key

        if cantidad_usuarios > 0:

            token = str(
                payload.get(
                    "token",
                    ""
                )
            ).strip()

            if not token:
                raise HTTPException(
                    status_code=401,
                    detail="Token requerido"
                )

            usuario_actual = await verificar_token(
                token,
                db
            )

            if (
                usuario_actual.empresa_uuid
                != empresa_uuid
            ):
                raise HTTPException(
                    status_code=403,
                    detail="La empresa no coincide"
                )

        else:

            token_tmp = str(
                payload.get(
                    "token_tmp",
                    ""
                )
            ).strip()

            if not token_tmp:
                raise HTTPException(
                    status_code=401,
                    detail="Token temporal requerido"
                )

            try:

                jwt.decode(
                    token_tmp,
                    JWT_SECRET,
                    algorithms=[JWT_ALGORITHM]
                )

            except Exception:

                raise HTTPException(
                    status_code=401,
                    detail="Token temporal inválido"
                )

        if not nombre:
            raise HTTPException(
                status_code=400,
                detail="Nombre requerido"
            )

        if not usuario:
            raise HTTPException(
                status_code=400,
                detail="Usuario requerido"
            )

        if not contraseña:
            raise HTTPException(
                status_code=400,
                detail="Contraseña requerida"
            )

        existe_usuario = await db.execute(
            select(User).where(
                User.empresa_uuid == empresa_uuid,
                User.usuario == usuario
            )
        )

        if existe_usuario.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail="El usuario ya existe"
            )

        while True:

            codigo = str(
                random.randint(
                    10000,
                    99999
                )
            )

            existe_codigo = await db.execute(
                select(User).where(
                    User.empresa_uuid == empresa_uuid,
                    User.codigo == codigo
                )
            )

            if not existe_codigo.scalar_one_or_none():
                break
            
        print("CONTRASEÑA:", contraseña)
        print("TIPO:", type(contraseña))
        print("LARGO:", len(contraseña))

        password_hash = pwd_context.hash(
            contraseña
        )

        nuevo_usuario = User(
            empresa_uuid=empresa_uuid,
            nombre=nombre,
            usuario=usuario,
            password_hash=password_hash,
            codigo=codigo,
            activo=True,
            permitir_nube=True,
            sync_status="synced",
            version=1
        )

        db.add(nuevo_usuario)

        await db.commit()

        await db.refresh(
            nuevo_usuario
        )

        return {
            "ok": True,
            "id": str(
                nuevo_usuario.id
            ),
            "empresa_uuid":
                nuevo_usuario.empresa_uuid,
            "nombre":
                nuevo_usuario.nombre,
            "usuario":
                nuevo_usuario.usuario,
            "codigo":
                nuevo_usuario.codigo,
            "activo":
                nuevo_usuario.activo,
            "permitir_nube":
                nuevo_usuario.permitir_nube,
            "sync_status":
                nuevo_usuario.sync_status,
            "version":
                nuevo_usuario.version,
            "created_at":
                nuevo_usuario.created_at.isoformat()
                if nuevo_usuario.created_at
                else None,
            "updated_at":
                nuevo_usuario.updated_at.isoformat()
                if nuevo_usuario.updated_at
                else None
        }

    except HTTPException:
        raise

    except Exception as e:

        print(
            "ERROR REGISTER USER:",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
        

@app.post("/login-user")
async def login_user(
    payload: dict,
    db: AsyncSession = Depends(get_db)
):

    usuario = str(
        payload.get("usuario", "")
    ).strip()

    contraseña = str(
        payload.get("password", "")
    ).strip()

    empresa_uuid = str(
        payload.get(
            "empresa_uuid",
            ""
        )
    ).strip()

    result = await db.execute(
        select(User).where(
            User.empresa_uuid == empresa_uuid,
            User.usuario == usuario,
            User.activo == True
        )
    )

    user = result.scalar_one_or_none()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña incorrectos"
        )

    if not pwd_context.verify(
        contraseña,
        user.password_hash
    ):

        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña incorrectos"
        )

    token = jwt.encode(
        {
            "user_id": str(user.id),
            "empresa_uuid": user.empresa_uuid,
            "usuario": user.usuario,
            "exp": datetime.utcnow() + timedelta(days=30)
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )

    return {
        "ok": True,
        "token": token,
        "id": str(user.id),
        "empresa_uuid": user.empresa_uuid,
        "nombre": user.nombre,
        "usuario": user.usuario,
        "codigo": user.codigo,
        "activo": user.activo,
        "permitir_nube": user.permitir_nube
    }
    
@app.post("/verify-password")
async def verify_password(
    payload: dict,
    db: AsyncSession = Depends(get_db)
):
    usuario = str(
        payload.get("usuario", "")
    ).strip()

    password = str(
        payload.get("password", "")
    ).strip()

    empresa_uuid = str(
        payload.get(
            "empresa_uuid",
            ""
        )
    ).strip()

    result = await db.execute(
        select(User).where(
            User.empresa_uuid == empresa_uuid,
            User.usuario == usuario
        )
    )

    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Usuario no encontrado"
        )

    if not pwd_context.verify(
        password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Contraseña incorrecta"
        )

    return {
        "ok": True
    }
    

@app.post("/empresa/dispositivo/solicitar")
async def solicitar_dispositivo(
    payload: dict,
    db: AsyncSession = Depends(get_db)
):

    empresa_uuid = payload["empresa_uuid"]
    dispositivo_uuid = payload["dispositivo_uuid"]
    nombre_dispositivo = payload["nombre_dispositivo"]

    q = await db.execute(
        select(EmpresaDispositivo).where(
            EmpresaDispositivo.empresa_uuid == empresa_uuid,
            EmpresaDispositivo.dispositivo_uuid == dispositivo_uuid
        )
    )

    dispositivo = q.scalar_one_or_none()

    if dispositivo:

        return {
            "ok": True,
            "estado": dispositivo.estado
        }

    q = await db.execute(
        select(Company).where(
            Company.uuid == empresa_uuid
        )
    )

    empresa = q.scalar_one_or_none()

    if not empresa:

        raise HTTPException(
            status_code=404,
            detail="Empresa no encontrada"
        )

    dispositivo = EmpresaDispositivo(
        empresa_uuid=empresa_uuid,
        dispositivo_uuid=dispositivo_uuid,
        nombre_dispositivo=nombre_dispositivo,
        estado="PENDIENTE"
    )

    db.add(dispositivo)

    await db.commit()

    await db.refresh(dispositivo)

    q = await db.execute(
        select(User).where(
            User.empresa_uuid == empresa_uuid,
            User.activo == True,
            User.permitir_nube == True
        )
    )

    admins = q.scalars().all()

    aprobar_url = (
    f"http://107.174.181.56:8000/"
    f"empresa/dispositivo/aprobar/"
    f"{dispositivo.id}"
)
    rechazar_url = (
        f"https://api.factuplus.com/"
        f"empresa/dispositivo/rechazar/"
        f"{dispositivo.id}"
    )

    for admin in admins:

        try:

            enviar_correo_aprobacion_dispositivo(
                admin.correo,
                nombre_dispositivo,
                empresa.nombre,
                aprobar_url,
                rechazar_url
            )

        except Exception as e:

            print(
                f"Error enviando correo a "
                f"{admin.correo}: {e}"
            )

    return {
        "ok": True,
        "estado": "PENDIENTE",
        "mensaje": (
            "Solicitud enviada. "
            "Esperando aprobación."
        )
    }   
@app.get("/empresa/dispositivo/estado")
async def verificar_estado(
    empresa_uuid: str,
    dispositivo_uuid: str,
    db: AsyncSession = Depends(get_db)
):

    q = await db.execute(
        text("""
            SELECT estado
            FROM empresa_dispositivos
            WHERE empresa_uuid = :empresa_uuid
            AND dispositivo_uuid = :dispositivo_uuid
        """),
        {
            "empresa_uuid": empresa_uuid,
            "dispositivo_uuid": dispositivo_uuid
        }
    )

    row = q.mappings().first()

    if not row:

        return {
            "estado": "NO_EXISTE"
        }

    return {
        "estado": row["estado"]
    }
    

    
@app.get("/empresa/restaurar/{empresa_uuid}")
async def restaurar_empresa(
    empresa_uuid: str,
    db: AsyncSession = Depends(get_db)
):

    empresa = (
        await db.execute(
            select(Company).where(
                Company.uuid == empresa_uuid
            )
        )
    ).scalar_one_or_none()

    if not empresa:
        raise HTTPException(
            status_code=404,
            detail="Empresa no encontrada"
        )

    usuarios = (
        await db.execute(
            select(User).where(
                User.empresa_uuid == empresa_uuid
            )
        )
    ).scalars().all()

    return {
        "empresa": {
            "uuid": empresa.uuid,
            "nombre": empresa.nombre,
            "rnc": empresa.rnc,
            "telefono": empresa.telefono,
            "direccion": empresa.direccion,
            "ncf": empresa.ncf
        },
        "usuarios": [
            {
                "id": str(u.id),
                "empresa_uuid": u.empresa_uuid,
                "nombre": u.nombre,
                "usuario": u.usuario,
                "codigo": u.codigo,
                "activo": u.activo,
                "permitir_nube": u.permitir_nube,
                "sync_status": u.sync_status,
                "version": u.version,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "updated_at": u.updated_at.isoformat() if u.updated_at else None
            }
            for u in usuarios
        ]
    }
    
from fastapi.responses import HTMLResponse

@app.get(
    "/empresa/dispositivo/aprobar/{id}"
)
async def aprobar_dispositivo(
    id: int,
    db: AsyncSession = Depends(get_db)
):

    await db.execute(
        text("""
            UPDATE empresa_dispositivos
            SET
                estado = 'APROBADO',
                fecha_aprobacion = NOW()
            WHERE id = :id
        """),
        {
            "id": id
        }
    )

    await db.commit()

    return HTMLResponse("""
        <h2>
            Dispositivo aprobado correctamente
        </h2>
    """)
    
@app.get(
    "/empresa/dispositivo/rechazar/{id}"
)
async def rechazar_dispositivo(
    id: int,
    db: AsyncSession = Depends(get_db)
):

    await db.execute(
        text("""
            UPDATE empresa_dispositivos
            SET estado = 'RECHAZADO'
            WHERE id = :id
        """),
        {
            "id": id
        }
    )

    await db.commit()

    return HTMLResponse("""
        <h2>
            Solicitud rechazada
        </h2>
    """)
    
def enviar_correo_aprobacion_dispositivo(
    destinatario: str,
    nombre_dispositivo: str,
    empresa_nombre: str,
    aprobar_url: str,
    rechazar_url: str
):

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    </head>

    <body style="
        margin:0;
        padding:0;
        background:#f4f6f9;
        font-family:Arial,Helvetica,sans-serif;
    ">

    <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
    <td align="center" style="padding:40px 20px;">

    <table width="650" cellpadding="0" cellspacing="0" style="
        background:white;
        border-radius:12px;
        overflow:hidden;
        box-shadow:0 5px 20px rgba(0,0,0,.08);
    ">

    <tr>
    <td style="
        background:#0d6efd;
        color:white;
        text-align:center;
        padding:30px;
    ">
        <h1 style="margin:0;">
            FactuPlus
        </h1>

        <p style="
            margin-top:10px;
            opacity:.9;
        ">
            Solicitud de Vinculación de Dispositivo
        </p>
    </td>
    </tr>

    <tr>
    <td style="padding:35px;">

        <h2 style="
            color:#212529;
            margin-top:0;
        ">
            Nuevo dispositivo solicitando acceso
        </h2>

        <p style="
            color:#495057;
            font-size:15px;
            line-height:1.7;
        ">
            Se ha detectado una nueva solicitud para vincular un
            dispositivo a la empresa:
        </p>

        <div style="
            background:#f8f9fa;
            border-left:5px solid #0d6efd;
            padding:20px;
            border-radius:8px;
            margin:20px 0;
        ">
            <p style="margin:0;">
                <strong>Empresa:</strong>
                {empresa_nombre}
            </p>

            <p style="
                margin-top:10px;
                margin-bottom:0;
            ">
                <strong>Dispositivo:</strong>
                {nombre_dispositivo}
            </p>
        </div>

        <p style="
            color:#6c757d;
            margin-bottom:30px;
        ">
            Si reconoces este dispositivo, puedes aprobarlo.
            En caso contrario, rechaza la solicitud.
        </p>

        <table width="100%">
        <tr>

        <td align="center">
            <a href="{aprobar_url}"
            style="
                display:inline-block;
                background:#198754;
                color:white;
                text-decoration:none;
                padding:14px 28px;
                border-radius:8px;
                font-weight:bold;
                font-size:15px;
            ">
                ✅ Aprobar Dispositivo
            </a>
        </td>

        <td align="center">
            <a href="{rechazar_url}"
            style="
                display:inline-block;
                background:#dc3545;
                color:white;
                text-decoration:none;
                padding:14px 28px;
                border-radius:8px;
                font-weight:bold;
                font-size:15px;
            ">
                ❌ Rechazar Dispositivo
            </a>
        </td>

        </tr>
        </table>

        <hr style="
            margin:35px 0;
            border:none;
            border-top:1px solid #e9ecef;
        ">

        <p style="
            color:#6c757d;
            font-size:13px;
            line-height:1.6;
        ">
            Por motivos de seguridad, solo aprueba dispositivos
            que pertenezcan a tu empresa.
        </p>

    </td>
    </tr>

    <tr>
    <td style="
        background:#f8f9fa;
        text-align:center;
        padding:20px;
        color:#6c757d;
        font-size:12px;
    ">
        © FactuPlus • Sistema de Facturación y Gestión Empresarial
    </td>
    </tr>

    </table>

    </td>
    </tr>
    </table>

    </body>
    </html>
    """

    msg = EmailMessage()

    msg["Subject"] = (
        "FactuPlus - Solicitud de acceso"
    )

    msg["From"] = EMAIL_FROM

    msg["To"] = destinatario

    msg.set_content(
        f"""
        Dispositivo:
        {nombre_dispositivo}

        Aprobar:
        {aprobar_url}

        Rechazar:
        {rechazar_url}
        """
    )

    msg.add_alternative(
        html,
        subtype="html"
    )

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT
    ) as smtp:

        smtp.login(
            SMTP_USER,
            SMTP_APP_PASSWORD
        )

        smtp.send_message(msg)

    return True
    
""" WEB PAGINA WEB """

class ListaEsperaCreate(BaseModel):
    empresa: str
    nombre: str
    correo: str
    telefono: str

@app.post("/lista-espera")
async def registrar_lista_espera(
    body: ListaEsperaCreate,
    db: AsyncSession = Depends(get_db)
):

    existe = await db.scalar(
        select(ListaEspera).where(
            ListaEspera.correo == body.correo
        )
    )

    if existe:
        raise HTTPException(
            status_code=400,
            detail="Este correo ya está registrado en la lista de espera."
        )

    registro = ListaEspera(
        empresa=body.empresa,
        nombre=body.nombre,
        correo=body.correo,
        telefono=body.telefono
    )

    db.add(registro)
    await db.commit()

    return {
        "ok": True
    }