# models.py
from sqlalchemy import JSON
from datetime import datetime, date
from decimal import Decimal
from sqlalchemy import (
    Boolean, DateTime, Integer, String, Numeric, Enum, SmallInteger, Date,
    ForeignKey, UniqueConstraint, func, text, BigInteger, Text, CheckConstraint,
    Index, CHAR, LargeBinary
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
    
    max_cajas: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        default=None
    )

    max_usuarios: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        default=None
    )

    max_roles: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        default=None
    )

    expires_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True
)

    created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
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
    DateTime(timezone=True),
    nullable=True
)

    updated_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=text("CURRENT_TIMESTAMP")
)

    created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
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

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    correo: Mapped[str | None] = mapped_column(
    String(255),
    nullable=True
)

    created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=text("CURRENT_TIMESTAMP")
)
    
    sync_cursor: Mapped[int] = mapped_column(
    BigInteger,
    unique=True,
    nullable=False
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
    DateTime(timezone=True),
    nullable=True
)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("CURRENT_TIMESTAMP")
    )

    created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=text("CURRENT_TIMESTAMP")
)
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )
    
class HistorialStock(Base):
    __tablename__ = "historial_stock"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    movimiento_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        unique=True,
        nullable=False,
        index=True
    )

    operacion_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    producto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "productos.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    tipo_movimiento: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    cantidad: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False
    )

    stock_antes: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False
    )

    stock_despues: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False
    )

    referencia: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    usuario_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "usuarios.id",
            ondelete="SET NULL"
        ),
        nullable=True,
        index=True
    )

    procesado_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    
    sync_cursor: Mapped[int] = mapped_column(
                BigInteger,
                unique=True,
                nullable=False
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
    
    venta_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
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
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("CURRENT_TIMESTAMP")
    )

    created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
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

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    cliente_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("clientes.id"),
        nullable=True
    )

    atendido_por: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=True
    )

    caja_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cajas.id"),
        nullable=True
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    monto_pagado: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    monto_pendiente: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    cambio: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )
    
    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    itbis: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    descuento_tipo: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="monto",
        server_default=text("'monto'")
    )

    descuento_porcentaje: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    descuento_monto: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    observacion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    motivo_anulacion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    tipo_pago: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    fecha: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    fecha_vencimiento: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pendiente",
        server_default=text("'pendiente'")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
    sync_cursor: Mapped[int] = mapped_column(
            BigInteger,
            unique=True,
            nullable=False
        )
    
class VentaDetalle(Base):

    __tablename__ = "venta_detalle"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    venta_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ventas.id", ondelete="CASCADE"),
        nullable=True
    )

    producto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("productos.id"),
        nullable=False
    )

    cantidad: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False
    )

    precio_unitario: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    descuento_tipo: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="monto",
        server_default=text("'monto'")
    )

    descuento_porcentaje: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

    descuento_monto: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

    descuentos_promocionales: Mapped[dict | list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb")
    )

    tasa_itbis: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )
    
    itbis: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

  

    itbis_neto: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

    reduccion_itbis: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

    base_imponible: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )

    descuento_global_asignado: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
        server_default=text("0")
    )


    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )
    
class Pago(Base):

    __tablename__ = "pagos"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )
    
    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    cliente_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("clientes.id"),
        nullable=True
    )

    venta_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ventas.id", ondelete="CASCADE"),
        nullable=False
    )

    metodo_pago_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("metodos_pago.id"),
        nullable=False
    )

    monto: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    referencia: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    autorizacion: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    ultimos_4: Mapped[str | None] = mapped_column(
        String(4),
        nullable=True
    )

    banco: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    observacion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="aprobado",
        server_default=text("'aprobado'")
    )

    fecha: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=text("CURRENT_TIMESTAMP")
)

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
    
    sync_cursor: Mapped[int] = mapped_column(
                    BigInteger,
                    unique=True,
                    nullable=False
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
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    fecha_cierre: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=func.now()
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    
    sync_cursor: Mapped[int] = mapped_column(
                    BigInteger,
                    unique=True,
                    nullable=False
                )
    
class UnidadMedida(Base):

    __tablename__ = "unidades_medida"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    plural: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    permitir_decimal: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False
    )

    version: Mapped[int] = mapped_column(
        Integer,
        default=1
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )
   
class Permiso(Base):

    __tablename__ = "permisos"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    clave: Mapped[str] = mapped_column(
        String,
        unique=True,
        nullable=False
    )

    descripcion: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    modulo: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )   
    
class RolPermiso(Base):

    __tablename__ = "rol_permisos"

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    rol_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "roles.id",
            ondelete="CASCADE"
        ),
        primary_key=True
    )

    permiso_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "permisos.id",
            ondelete="CASCADE"
        ),
        primary_key=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        default=1
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )
    
class Rol(Base):

    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    descripcion: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        default=1
    )
    
    nivel: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )
    
    sync_cursor: Mapped[int] = mapped_column(
                    BigInteger,
                    unique=True,
                    nullable=False
                )
    
class UsuarioRol(Base):

    __tablename__ = "usuario_roles"

    usuario_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "usuarios.id",
            ondelete="CASCADE"
        ),
        primary_key=True
    )

    rol_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "roles.id",
            ondelete="CASCADE"
        ),
        primary_key=True
    )

    empresa_uuid: Mapped[UUID] = mapped_column(
    PG_UUID(as_uuid=True),
    nullable=False,
    index=True
)

    version: Mapped[int] = mapped_column(
        Integer,
        default=1
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        default="synced"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    sync_cursor: Mapped[int] = mapped_column(
                    BigInteger,
                    unique=True,
                    nullable=False
                )

class Producto(Base):

    __tablename__ = "productos"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    codigo_barras: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    codigo_balanza: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    codigo_interno: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    es_balanza: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false")
    )

    nombre: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    precio: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    margen: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )
    
    costo: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    stock: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    stock_minimo: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    itbis: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    unidad_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "unidades_medida.id",
            ondelete="RESTRICT"
        ),
        nullable=False
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true")
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

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )
    
    sync_cursor: Mapped[int] = mapped_column(
                    BigInteger,
                    unique=True,
                    nullable=False
                )
    
class MetodoPago(Base):

    __tablename__ = "metodos_pago"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true")
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

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )
    
class Cliente(Base):

    __tablename__ = "clientes"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    codigo: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    nombre: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    telefono: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    email: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    direccion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ciudad: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    sector: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    documento: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    limite_credito: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    balance: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    estado_credito: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="al_dia",
        server_default=text("'al_dia'")
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true")
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

class Suplidor(Base):

    __tablename__ = "suplidores"

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

    numero_suplidor: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        autoincrement=True
    )

    nombre: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    rnc: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    contacto: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    correo: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    telefono: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True
    )

    direccion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )
  
  
class Compra(Base):

    __tablename__ = "compras"

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

    numero_compra: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        autoincrement=True
    )

    suplidor_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "suplidores.id",
            ondelete="RESTRICT"
        ),
        nullable=False
    )

    usuario_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "usuarios.id",
            ondelete="SET NULL"
        ),
        nullable=True
    )

    numero_factura: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    descuento: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    itbis: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )
    
class CompraDetalle(Base):

    __tablename__ = "compras_detalles"

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

    compra_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "compras.id",
            ondelete="CASCADE"
        ),
        nullable=False
    )

    producto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "productos.id",
            ondelete="RESTRICT"
        ),
        nullable=False
    )

    cantidad: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False
    )

    costo_unitario: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )
    
    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )
    
class Devolucion(Base):

    __tablename__ = "devoluciones"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
            String(36),
            nullable=False,
            index=True
        )

    venta_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ventas.id"),
        nullable=False,
        index=True
    )

    cliente_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("clientes.id"),
        nullable=True
    )

    caja: Mapped[UUID] = mapped_column(
    PG_UUID(as_uuid=True),
    ForeignKey(
        "cajas_config.id",
        ondelete="RESTRICT"
    ),
    nullable=False
)

    ncf: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    ncf_modificado: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    fecha: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    tipo: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    itbis: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    motivo: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="completada",
        server_default=text("'completada'")
    )

    usuario_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("usuarios.id"),
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False
    )
    
class DevolucionDetalle(Base):

    __tablename__ = "devolucion_detalle"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
            String(36),
            nullable=False,
            index=True
        )

    devolucion_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "devoluciones.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    venta_detalle_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("venta_detalle.id"),
        nullable=False,
        index=True
    )

    producto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("productos.id"),
        nullable=False,
        index=True
    )

    cantidad: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False
    )

    precio_unitario: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    itbis: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    sync_status: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("NOW()")
    )
    
class Cotizacion(Base):

    __tablename__ = "cotizaciones"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    cliente_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("clientes.id"),
        nullable=True
    )

    usuario_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )
    
    modificado_por: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )

    fecha: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    fecha_vencimiento: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="borrador",
        server_default=text("'borrador'")
    )

    subtotal: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    descuento: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    impuesto: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    observaciones: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    condiciones: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    venta_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )
    
class CotizacionDetalle(Base):

    __tablename__ = "cotizacion_detalles"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )
    
    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    cotizacion_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("cotizaciones.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    producto_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )

    descripcion: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    cantidad: Mapped[Decimal] = mapped_column(
        Numeric(15, 4),
        nullable=False,
        default=1,
        server_default=text("1")
    )

    precio: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    descuento: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    impuesto: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    total: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )
    

class Descuento(Base):

    __tablename__ = "descuentos"

    __table_args__ = (
        CheckConstraint(
            "valor >= 0",
            name="descuentos_valor_check"
        ),
        CheckConstraint(
            "tipo <> 'porcentaje' OR valor <= 100",
            name="descuentos_porcentaje_check"
        ),
        CheckConstraint(
            "fecha_fin IS NULL OR fecha_inicio IS NULL OR fecha_fin >= fecha_inicio",
            name="descuentos_fechas_check"
        ),
        CheckConstraint(
            """
            (usar_producto_beneficiario AND beneficiario_tipo IS NOT NULL)
            OR
            (NOT usar_producto_beneficiario AND beneficiario_tipo IS NULL)
            """,
            name="descuentos_beneficiario_config_check"
        ),
        CheckConstraint(
            """
            beneficiario_tipo IS NULL
            OR beneficiario_tipo IN ('menor_precio', 'mayor_precio')
            """,
            name="descuentos_beneficiario_tipo_check"
        ),
        CheckConstraint(
            "tipo IN ('porcentaje', 'monto_fijo')",
            name="descuentos_tipo_check"
        ),
        CheckConstraint(
            "aplicar_a IN ('venta', 'productos')",
            name="descuentos_aplicar_a_check"
        ),
        CheckConstraint(
            "operador_condiciones IN ('AND', 'OR')",
            name="descuentos_operador_condiciones_check"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String,
        nullable=False,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    tipo: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    valor: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    aplicar_a: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="productos",
        server_default=text("'productos'")
    )

    usar_condiciones: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("FALSE")
    )

    operador_condiciones: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="AND",
        server_default=text("'AND'")
    )

    fecha_inicio: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    fecha_fin: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("TRUE")
    )

    usar_producto_beneficiario: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("FALSE")
    )

    aplicar_a_todas_unidades_beneficiario: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("FALSE")
    )

    beneficiario_tipo: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    beneficiario_valor: Mapped[Decimal | None] = mapped_column(
        Numeric(15, 2),
        nullable=True
    )

    se_repite: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("FALSE")
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )


class DescuentoProducto(Base):

    __tablename__ = "descuento_productos"

    __table_args__ = (
        UniqueConstraint(
            "descuento_id",
            "producto_id",
            name="descuento_productos_unique"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    descuento_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "descuentos.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    producto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "productos.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )
    
class DescuentoCliente(Base):

    __tablename__ = "descuento_clientes"

    __table_args__ = (
        UniqueConstraint(
            "descuento_id",
            "cliente_id",
            name="descuento_clientes_unique"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )

    descuento_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "descuentos.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    cliente_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "clientes.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    sync_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )
    
class DescuentoCondicion(Base):

    __tablename__ = "descuento_condiciones"

    __table_args__ = (
        CheckConstraint(
            "tipo IN ('cantidad', 'cantidad_productos_diferentes', 'importe', 'cliente', 'forma_pago', 'dia_semana', 'horario')",
            name="descuento_condiciones_tipo_check"
        ),
        CheckConstraint(
            "operador IN ('minimo', 'maximo', 'exacto', 'rango', 'igual')",
            name="descuento_condiciones_operador_check"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True
    )

    descuento_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "descuentos.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    tipo: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    operador: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    valor_numero: Mapped[Decimal | None] = mapped_column(
        Numeric(15, 2),
        nullable=True
    )

    valor_numero_2: Mapped[Decimal | None] = mapped_column(
        Numeric(15, 2),
        nullable=True
    )

    valor_texto: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    valor_texto_2: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    producto_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "productos.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    cliente_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "clientes.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    metodo_pago_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "metodos_pago.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )
       
class DescuentoDia(Base):

    __tablename__ = "descuento_dias"

    __table_args__ = (
        UniqueConstraint(
            "descuento_id",
            "dia",
            name="descuento_dias_unique"
        ),
        CheckConstraint(
            "dia BETWEEN 0 AND 6",
            name="descuento_dias_dia_check"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True
    )

    descuento_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "descuentos.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    dia: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

class AuditoriaInventario(Base):

    __tablename__ = "auditorias_inventario"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True
    )

    nombre: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    tipo: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="general",
        server_default=text("'general'")
    )

    estado: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="preparacion",
        server_default=text("'preparacion'")
    )

    fecha_inicio: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    fecha_finalizacion: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    usuario_creador: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False
    )

    observaciones: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    total_productos: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0")
    )

    productos_contados: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0")
    )

    productos_con_diferencias: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0")
    )
    
    fecha_programada: Mapped[date | None] = mapped_column(
        Date,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default=text("1"),
        unique=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )
    
""" class Gasto(Base):

    __tablename__ = "gastos"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True
    )

    concepto: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    categoria: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    proveedor_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )

    monto: Mapped[float] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    monto_pagado: Mapped[float] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    monto_pendiente: Mapped[float] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=0,
        server_default=text("0")
    )

    es_recurrente: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("FALSE")
    )

    frecuencia: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    dia_recurrencia: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    fecha_recurrencia: Mapped[date | None] = mapped_column(
        Date,
        nullable=True
    )

    fecha: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        server_default=text("CURRENT_DATE")
    )

    fecha_vencimiento: Mapped[date | None] = mapped_column(
        Date,
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pendiente",
        server_default=text("'pendiente'")
    )

    observacion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

class GastoPago(Base):

    __tablename__ = "gastos_pagos"

    __table_args__ = (
        CheckConstraint(
            "pago_periodo = DATE_TRUNC('month', pago_periodo)::date",
            name="gastos_pagos_pago_periodo_primer_dia_chk"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True
    )

    gasto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "gastos.id",
            ondelete="NO ACTION"
        ),
        nullable=False,
        index=True
    )

    pago_periodo: Mapped[date] = mapped_column(
        Date,
        nullable=False
    )

    monto: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    fecha_pago: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    tipo_pago: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    observacion: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )
    
class GastoObligacion(Base):

    __tablename__ = "gastos_obligaciones"

    __table_args__ = (
        UniqueConstraint(
            "gasto_id",
            "periodo",
            name="gastos_obligaciones_gasto_id_periodo_key"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True
    )

    gasto_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "gastos.id",
            ondelete="NO ACTION"
        ),
        nullable=False,
        index=True
    )

    periodo: Mapped[date] = mapped_column(
        Date,
        nullable=False
    )

    monto: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    monto_pagado: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default=text("0")
    )

    monto_pendiente: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default=text("0")
    )

    fecha_vencimiento: Mapped[date | None] = mapped_column(
        Date,
        nullable=True
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pendiente",
        server_default=text("'pendiente'")
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        unique=True,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()")
    )
    
 """
 
 
class SecuenciaECF(Base):

    __tablename__ = "secuencias_ecf"

    __table_args__ = (

        UniqueConstraint(
            "empresa_uuid",
            "tipo_ecf",
            name="secuencias_ecf_tipo_empresa_unique"
        ),

        CheckConstraint(
            "numero_inicial >= 0",
            name="secuencias_ecf_numero_inicial_check"
        ),

        CheckConstraint(
            "numero_final >= numero_inicial",
            name="secuencias_ecf_numero_final_check"
        ),

        CheckConstraint(
            "ultimo_numero >= 0 AND ultimo_numero <= numero_final",
            name="secuencias_ecf_ultimo_numero_check"
        ),

        CheckConstraint(
            """
            fecha_vencimiento IS NULL
            OR fecha_inicio IS NULL
            OR fecha_vencimiento >= fecha_inicio
            """,
            name="secuencias_ecf_fechas_check"
        ),

        Index(
            "idx_secuencias_ecf_empresa",
            "empresa_uuid"
        ),

        Index(
            "idx_secuencias_ecf_empresa_activo",
            "empresa_uuid",
            "activo"
        ),

        Index(
            "idx_secuencias_ecf_empresa_sync_cursor",
            "empresa_uuid",
            "sync_cursor"
        )
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    tipo_ecf: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    prefijo: Mapped[str] = mapped_column(
        String(10),
        nullable=False
    )

    numero_inicial: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    numero_final: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False
    )

    ultimo_numero: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default=text("0")
    )

    fecha_inicio: Mapped[date | None] = mapped_column(
        Date,
        nullable=True
    )

    fecha_vencimiento: Mapped[date | None] = mapped_column(
        Date,
        nullable=True
    )

    activo: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true")
    )

    sync_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="synced",
        server_default=text("'synced'")
    )

    sync_cursor: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True
    )

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    
""" Receptor de la DGII """


class EcfFirmadorTicket(Base):

    __tablename__ = "ecf_firmador_tickets"

    __table_args__ = (
        UniqueConstraint(
            "ticket_hash",
            name="ecf_firmador_tickets_hash_unique"
        ),

        Index(
            "idx_ecf_firmador_tickets_expira",
            "expires_at",
            postgresql_where=text("consumed_at IS NULL")
        )
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )

    ticket_hash: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    dispositivo_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    usuario_id: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


class EcfRecibido(Base):

    __tablename__ = "ecf_recibidos"

    __table_args__ = (

        UniqueConstraint(
            "empresa_uuid",
            "rnc_emisor",
            "encf",
            name="uq_ecf_recibido_empresa_emisor_encf"
        ),

        CheckConstraint(
            """
            estado_procesamiento IN (
                'recibido',
                'validado',
                'pendiente_revision',
                'procesado',
                'rechazado',
                'error'
            )
            """,
            name="chk_ecf_recibido_estado"
        ),

        Index(
            "idx_ecf_recibidos_empresa_fecha",
            "empresa_uuid",
            "created_at"
        )
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )

    empresa_uuid: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    tipo_ecf: Mapped[str] = mapped_column(
        String(3),
        nullable=False
    )

    rnc_emisor: Mapped[str] = mapped_column(
        String(11),
        nullable=False
    )

    rnc_comprador: Mapped[str] = mapped_column(
        String(11),
        nullable=False
    )

    encf: Mapped[str] = mapped_column(
        String(13),
        nullable=False
    )

    xml_original: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    xml_sha256: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False
    )

    estado_procesamiento: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pendiente_revision",
        server_default=text("'pendiente_revision'")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now()
    )


class EcfAcuse(Base):

    __tablename__ = "ecf_acuses"

    __table_args__ = (

        UniqueConstraint(
            "ecf_recibido_id",
            name="uq_ecf_acuses_recibido"
        ),

        CheckConstraint(
            """
            estado IN (
                'pendiente_firmar',
                'firmado',
                'enviado',
                'error'
            )
            """,
            name="chk_ecf_acuse_estado"
        ),

        CheckConstraint(
            """
            codigo_estado IS NULL
            OR codigo_estado IN (0, 1)
            """,
            name="chk_ecf_acuse_codigo"
        ),

        CheckConstraint(
            """
            codigo_motivo IS NULL
            OR codigo_motivo BETWEEN 1 AND 4
            """,
            name="chk_ecf_acuse_motivo"
        )
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )

    ecf_recibido_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "ecf_recibidos.id",
            ondelete="CASCADE"
        ),
        nullable=False
    )

    estado: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pendiente_firmar",
        server_default=text("'pendiente_firmar'")
    )

    codigo_estado: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True
    )

    codigo_motivo: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True
    )

    xml_arecf_firmado: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    fecha_generacion: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    fecha_envio: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    error_detalle: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now()
    )


class EcfRecepcionIntento(Base):

    __tablename__ = "ecf_recepcion_intentos"

    __table_args__ = (

        CheckConstraint(
            """
            estado IN (
                'recibido',
                'procesado',
                'duplicado',
                'rechazado',
                'error'
            )
            """,
            name="chk_ecf_recepcion_intento_estado"
        ),

        Index(
            "idx_ecf_recepcion_intentos_empresa_fecha",
            "empresa_uuid",
            "fecha_recepcion"
        ),

        Index(
            "idx_ecf_recepcion_intentos_documento",
            "rnc_emisor",
            "encf"
        )
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()")
    )

    empresa_uuid: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    ecf_recibido_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "ecf_recibidos.id",
            ondelete="SET NULL"
        ),
        nullable=True
    )

    rnc_emisor: Mapped[str | None] = mapped_column(
        String(11),
        nullable=True
    )

    rnc_comprador: Mapped[str | None] = mapped_column(
        String(11),
        nullable=True
    )

    encf: Mapped[str | None] = mapped_column(
        String(13),
        nullable=True
    )

    xml_sha256: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False
    )

    xml_original: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    estado: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="recibido",
        server_default=text("'recibido'")
    )

    codigo_respuesta: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    detalle_respuesta: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    http_status: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    detalle: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    xml_arecf_firmado: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    fecha_recepcion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


class EcfCertificado(Base):
    __tablename__ = "ecf_certificados"

    __table_args__ = (
        UniqueConstraint(
            "empresa_uuid",
            "fingerprint_sha256",
            name="uq_ecf_certificado_empresa_fingerprint"
        ),
        CheckConstraint(
            """
            estado IN (
                'pendiente_validacion',
                'activo',
                'reemplazado',
                'revocado',
                'expirado'
            )
            """,
            name="ecf_certificados_estado_check"
        ),
        Index(
            "ecf_certificado_unico_activo_empresa",
            "empresa_uuid",
            unique=True,
            postgresql_where=text("estado = 'activo'")
        ),
        Index(
            "ecf_certificados_empresa_idx",
            "empresa_uuid"
        )
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4
    )

    empresa_uuid: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False
    )

    fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )

    serial_number: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    subject_dn: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    issuer_dn: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    valid_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    valid_to: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    payload_cifrado: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False
    )

    clave_cifrada: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False
    )

    nonce: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False
    )

    proveedor_claves: Mapped[str] = mapped_column(
        String(30),
        nullable=False
    )

    referencia_clave: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    version_cifrado: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1")
    )

    estado: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pendiente_validacion",
        server_default=text("'pendiente_validacion'")
    )

    creado_por: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False
    )

    creado_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    revocado_por: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True
    )

    revocado_en: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
""" WEB PAGINA """

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
    DateTime(timezone=True),
    nullable=False,
    server_default=text("CURRENT_TIMESTAMP")
)

    fecha_aprobacion: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True
)


class ListaEspera(Base):

    __tablename__ = "lista_espera"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True
    )

    empresa: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    nombre: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    correo: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True
    )

    telefono: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    seleccionado: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false")
    )

    created_at: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    nullable=False,
    server_default=text("CURRENT_TIMESTAMP")
)