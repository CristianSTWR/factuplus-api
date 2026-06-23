# models.py
from sqlalchemy import JSON
from datetime import datetime
from decimal import Decimal
from sqlalchemy import (
    Boolean, DateTime, Integer, String, Numeric, Enum, 
    ForeignKey, UniqueConstraint, func, text, BigInteger, Text, CheckConstraint
)

import enum

from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from enum import Enum as PyEnum
from sqlalchemy.orm import relationship, Mapped, mapped_column
from db import Base
from uuid import UUID, uuid4
from sqlalchemy.dialects.postgresql import JSONB

class LicenseStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"

class License(Base):
    __tablename__ = "licenses"

    id: Mapped[UUID] = mapped_column(
    PG_UUID(as_uuid=True),
    primary_key=True,
    default=uuid4,
    index=True
)

    user_id: Mapped[str] = mapped_column(String(128), nullable=False)

    license_key: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True
    )
    
    suspicious: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,                # ORM
        server_default=text("false")  # DB
    )

    suspicious_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    status: Mapped[LicenseStatus] = mapped_column(
        Enum(LicenseStatus, name="license_status"),
        nullable=False,
        server_default=text("'active'")
    )

    max_devices: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("1")
    )

    expires_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --------------------
    # PayPal / Billing
    # --------------------

    paypal_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    last_payment_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    last_payment_amount: Mapped[float | None] = mapped_column(
        Numeric(12, 2),
        nullable=True
    )

    last_payment_currency: Mapped[str | None] = mapped_column(
        String(8),
        nullable=True
    )

    next_billing_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    last_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    cancel_requested: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,                 # ORM
        server_default=text("false")   # DB
    )

    # ✅ NUEVO: hasta cuándo tiene acceso premium
    paid_through: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # ✅ NUEVO: cuándo se detectó la cancelación
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # --------------------
    # Relationships
    # --------------------

    devices: Mapped[list["LicenseDevice"]] = relationship(
        "LicenseDevice",
        back_populates="license",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="license",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

class LicenseDevice(Base):
    __tablename__ = "license_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ✅ FK correcto: licenses.license_key
    license_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="CASCADE"),
        nullable=False
    )

    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    license: Mapped["License"] = relationship("License", back_populates="devices")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_license_device"),
    )


class PaypalEnv(PyEnum):
    sandbox = "sandbox"
    live = "live"


class Planes(Base):
    __tablename__ = "billing_plan"

    # PK
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    # Entorno PayPal
    env: Mapped[PaypalEnv] = mapped_column(
        Enum(PaypalEnv, name="paypal_env"),
        nullable=False
    )

    # Clave interna (premium_monthly, premium_yearly, etc.)
    plan_key: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    # Nombre visible (LUNA Premium Mensual)
    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False
    )

    # Moneda (USD)
    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False
    )

    # Precio (24.99)
    price: Mapped[float] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    # IDs PayPal
    paypal_product_id: Mapped[str] = mapped_column(
        String(40),
        nullable=False
    )

    paypal_plan_id: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        unique=True
    )

    # Activo / inactivo
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True
    )

    # Fechas
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<Plan id={self.id} key={self.plan_key} "
            f"price={self.price} {self.currency} env={self.env}>"
        )

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    token: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)

    # ✅ FK correcto: licenses.license_key
    license_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("licenses.license_key", ondelete="CASCADE"),
        nullable=False
    )

    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    license: Mapped["License"] = relationship("License", back_populates="refresh_tokens")

    __table_args__ = (
        UniqueConstraint("license_key", "device_id", name="uq_refresh_per_install"),
    )
    
class PaypalSubscription(Base):
    __tablename__ = "paypal_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    env: Mapped[PaypalEnv] = mapped_column(
        Enum(PaypalEnv, name="paypal_env"),
        nullable=False
    )

    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    paypal_plan_id: Mapped[str] = mapped_column(String(64), nullable=False)

    paypal_subscription_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="CREATED")
    approve_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    subscriber_email = mapped_column(String) 

    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
class PaypalWebhookEvent(Base):
    __tablename__ = "paypal_webhook_event"

    __table_args__ = (
        UniqueConstraint("env", "paypal_event_id", name="uq_webhook_env_event"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    env: Mapped[PaypalEnv] = mapped_column(
        Enum(PaypalEnv, name="paypal_env"),
        nullable=False
    )

    paypal_event_id: Mapped[str] = mapped_column(Text, nullable=False)  # body["id"]
    event_type: Mapped[str] = mapped_column(Text, nullable=False)

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    processing_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=text("'received'")  # received|processed|failed
    )

    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
class Company(Base):

    __tablename__ = "empresa"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    uuid: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid4()),
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    
    version: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))

    telefono: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    rnc: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    direccion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ncf: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false")
    )

    uso_balanza: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false")
    )

    facturas_electronicas: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced",
        server_default=text("'synced'")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
class User(Base):

    __tablename__ = "usuarios"

    id: Mapped[UUID] = mapped_column(
    PG_UUID(as_uuid=True),
    primary_key=True,
    default=uuid4,
    index=True
)
    empresa_uuid: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    usuario: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true")
    )

    permitir_nube: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("false")
    )

    token: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )
    
    codigo: Mapped[str] = mapped_column(
        String(5),
        unique=True,
        nullable=False,
        index=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        server_default=text("1")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced",
        server_default=text("'synced'")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
    correo: Mapped[str | None] = mapped_column(
    String(255),
    nullable=True
)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
class CajaConfig(Base):

    __tablename__ = "cajas_config"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False
    )

    activa: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        server_default=text("1")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced",
        server_default=text("'synced'")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("CURRENT_TIMESTAMP")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
class CajaMovimiento(Base):

    __tablename__ = "caja_movimientos"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True
    )

    caja_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cajas.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    usuario_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=True
    )

    venta_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("ventas.id"),
        nullable=True
    )

    tipo: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    monto: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False
    )

    descripcion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    solicitado_por: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=True
    )

    autorizado_por: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=True
    )

    requiere_autorizacion: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false")
    )

    estado_autorizacion: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="no_requiere",
        server_default=text("'no_requiere'")
    )
    
    fecha_autorizacion: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True
)

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced",
        server_default=text("'synced'")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("CURRENT_TIMESTAMP")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    __table_args__ = (
        CheckConstraint(
            "tipo IN ('apertura', 'venta', 'ingreso', 'egreso', 'devolucion', 'cierre')",
            name="check_caja_movimiento_tipo"
        ),

        CheckConstraint(
            "monto >= 0",
            name="check_caja_movimiento_monto"
        ),

        CheckConstraint(
            "estado_autorizacion IN ('pendiente', 'aprobado', 'rechazado', 'no_requiere')",
            name="check_caja_movimiento_estado_autorizacion"
        ),
    )
    
class Venta(Base):

    __tablename__ = "ventas"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
        index=True
    )

    cliente_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("clientes.id"),
        nullable=True
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    monto_pagado: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        default=0,
        server_default=text("0")
    )

    monto_pendiente: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        default=0,
        server_default=text("0")
    )

    fecha: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    fecha_vencimiento: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        default="pendiente",
        server_default=text("'pendiente'")
    )
    
class Caja(Base):

    __tablename__ = "cajas"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True
    )

    caja_config_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cajas_config.id", ondelete="CASCADE"),
        nullable=False
    )
    
    numero_sesion: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )

    usuario_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=False
    )

    monto_inicial: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    monto_contado: Mapped[Decimal | None] = mapped_column(
        Numeric(10, 2),
        nullable=True
    )

    diferencia: Mapped[Decimal | None] = mapped_column(
        Numeric(10, 2),
        nullable=True
    )

    observacion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    motivo_cierre: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    tipo_cierre: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    cerrada_por: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="abierta",
        server_default=text("'abierta'")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        server_default=text("'pending'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    fecha_apertura: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    fecha_cierre: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("CURRENT_TIMESTAMP")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
class EmpresaDispositivo(Base):

    __tablename__ = "empresa_dispositivos"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    empresa_uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True
    )

    dispositivo_uuid: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True
    )

    nombre_dispositivo: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PENDIENTE",
        server_default=text("'PENDIENTE'")
    )

    fecha_solicitud: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    fecha_aprobacion: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )