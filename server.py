from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import io
import csv
import logging
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Literal

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, ConfigDict

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_ALGORITHM = "HS256"
JWT_SECRET = os.environ['JWT_SECRET']
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@kkpstores.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="KKP Stores API")
api_router = APIRouter(prefix="/api")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(user_id: str, email: str, role: str, store_id: str = "") -> str:
    payload = {
        "sub": user_id, "email": email, "role": role, "store_id": store_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "refresh",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    response.set_cookie("access_token", access_token, httponly=True, secure=False, samesite="lax", max_age=43200, path="/")
    response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        # Ensure store_id is always present
        if not user.get("store_id"):
            default = await db.stores.find_one({}, {"_id": 0})
            if default:
                user["store_id"] = default["id"]
                await db.users.update_one({"id": user["id"]}, {"$set": {"store_id": default["id"]}})
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(*roles: str):
    async def checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[Literal["admin", "manager", "cashier"]] = "cashier"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    created_at: str


class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    sku: str
    barcode: Optional[str] = ""
    category: str  # e.g., "Textiles", "Home Utility"
    sub_category: Optional[str] = ""
    unit: str = "pcs"  # pcs, meter, kg, set
    purchase_price: float = 0
    sale_price: float = 0
    gst_percent: float = 5
    stock_qty: float = 0
    low_stock_threshold: float = 5
    description: Optional[str] = ""
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


class ProductCreate(BaseModel):
    name: str
    sku: str
    barcode: Optional[str] = ""
    category: str
    sub_category: Optional[str] = ""
    unit: str = "pcs"
    purchase_price: float = 0
    sale_price: float = 0
    gst_percent: float = 5
    stock_qty: float = 0
    low_stock_threshold: float = 5
    description: Optional[str] = ""


class Customer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    phone: Optional[str] = ""
    email: Optional[str] = ""
    address: Optional[str] = ""
    gstin: Optional[str] = ""
    created_at: str = Field(default_factory=now_iso)


class CustomerCreate(BaseModel):
    name: str
    phone: Optional[str] = ""
    email: Optional[str] = ""
    address: Optional[str] = ""
    gstin: Optional[str] = ""


class Supplier(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    contact_person: Optional[str] = ""
    phone: Optional[str] = ""
    email: Optional[str] = ""
    address: Optional[str] = ""
    gstin: Optional[str] = ""
    created_at: str = Field(default_factory=now_iso)


class SupplierCreate(BaseModel):
    name: str
    contact_person: Optional[str] = ""
    phone: Optional[str] = ""
    email: Optional[str] = ""
    address: Optional[str] = ""
    gstin: Optional[str] = ""


class SaleItem(BaseModel):
    product_id: str
    name: str
    sku: str
    quantity: float
    unit_price: float
    gst_percent: float
    discount: float = 0
    line_total: float  # after discount + tax


class SaleCreate(BaseModel):
    customer_id: Optional[str] = ""
    customer_name: Optional[str] = "Walk-in Customer"
    items: List[SaleItem]
    discount_total: float = 0
    payment_method: str = "cash"  # cash, card, upi
    notes: Optional[str] = ""


class PurchaseItem(BaseModel):
    product_id: str
    name: str
    sku: str
    quantity: float
    unit_cost: float
    line_total: float


class PurchaseCreate(BaseModel):
    supplier_id: str
    supplier_name: str
    items: List[PurchaseItem]
    notes: Optional[str] = ""


class AIInsightRequest(BaseModel):
    focus: Optional[str] = "general"  # general | low_stock | top_sellers | profit


# -----------------------------------------------------------------------------
# Store Models
# -----------------------------------------------------------------------------
class Store(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    address: Optional[str] = ""
    phone: Optional[str] = ""
    gstin: Optional[str] = ""
    owner_id: str
    created_at: str = Field(default_factory=now_iso)


class StoreCreate(BaseModel):
    name: str
    address: Optional[str] = ""
    phone: Optional[str] = ""
    gstin: Optional[str] = ""


class StoreSwitch(BaseModel):
    store_id: str


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Literal["admin", "manager", "cashier"] = "cashier"


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[Literal["admin", "manager", "cashier"]] = None
    password: Optional[str] = None


# -----------------------------------------------------------------------------
# Auth Routes
# -----------------------------------------------------------------------------
@api_router.post("/auth/register")
async def register(payload: RegisterRequest, response: Response):
    """Bootstrap endpoint — only allowed when there are zero users in the DB.
    After the first admin is created, new staff must be added by an existing
    admin via POST /api/users."""
    user_count = await db.users.count_documents({})
    if user_count > 0:
        raise HTTPException(
            status_code=403,
            detail="Public registration is disabled. Ask your administrator to create your account.",
        )
    email = payload.email.lower()
    user_id = str(uuid.uuid4())
    role = "admin"  # First user is always admin
    # Auto-create a store for the new admin
    store_doc = Store(name=f"{payload.name}'s Store", owner_id=user_id).model_dump()
    await db.stores.insert_one(store_doc)
    store_id = store_doc["id"]
    user_doc = {
        "id": user_id,
        "name": payload.name,
        "email": email,
        "password_hash": hash_password(payload.password),
        "role": role,
        "store_id": store_id,
        "created_at": now_iso(),
    }
    await db.users.insert_one(user_doc)
    at = create_access_token(user_id, email, role, store_id)
    rt = create_refresh_token(user_id)
    set_auth_cookies(response, at, rt)
    return {"id": user_id, "name": payload.name, "email": email, "role": role, "store_id": store_id, "created_at": user_doc["created_at"], "token": at}


@api_router.post("/auth/login")
async def login(payload: LoginRequest, response: Response):
    email = payload.email.lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    # Ensure store_id is set
    store_id = user.get("store_id", "")
    if not store_id:
        default = await db.stores.find_one({}, {"_id": 0})
        store_id = default["id"] if default else ""
        if store_id:
            await db.users.update_one({"id": user["id"]}, {"$set": {"store_id": store_id}})
    at = create_access_token(user["id"], user["email"], user["role"], store_id)
    rt = create_refresh_token(user["id"])
    set_auth_cookies(response, at, rt)
    return {
        "id": user["id"], "name": user["name"], "email": user["email"],
        "role": user["role"], "store_id": store_id, "created_at": user["created_at"], "token": at,
    }


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out"}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api_router.get("/users")
async def list_users(user: dict = Depends(require_role("admin"))):
    # List users in the current store
    users = await db.users.find({"store_id": user["store_id"]}, {"_id": 0, "password_hash": 0}).to_list(500)
    return users


@api_router.post("/users")
async def create_user(payload: UserCreate, user: dict = Depends(require_role("admin"))):
    email = payload.email.lower()
    exists = await db.users.find_one({"email": email})
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    new_doc = {
        "id": user_id,
        "name": payload.name,
        "email": email,
        "password_hash": hash_password(payload.password),
        "role": payload.role,
        "store_id": user["store_id"],
        "created_at": now_iso(),
    }
    await db.users.insert_one(new_doc)
    new_doc.pop("_id", None)
    new_doc.pop("password_hash", None)
    return new_doc


@api_router.patch("/users/{uid}")
async def update_user(uid: str, payload: UserUpdate, user: dict = Depends(require_role("admin"))):
    target = await db.users.find_one({"id": uid, "store_id": user["store_id"]})
    if not target:
        raise HTTPException(status_code=404, detail="User not found in your store")
    update = {}
    if payload.name is not None:
        update["name"] = payload.name
    if payload.role is not None:
        update["role"] = payload.role
    if payload.password:
        update["password_hash"] = hash_password(payload.password)
    if update:
        await db.users.update_one({"id": uid}, {"$set": update})
    fresh = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0})
    return fresh


@api_router.delete("/users/{uid}")
async def delete_user(uid: str, user: dict = Depends(require_role("admin"))):
    if uid == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    res = await db.users.delete_one({"id": uid, "store_id": user["store_id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found in your store")
    return {"message": "Deleted"}


# -----------------------------------------------------------------------------
# Stores
# -----------------------------------------------------------------------------
@api_router.get("/stores")
async def list_stores(user: dict = Depends(get_current_user)):
    if user["role"] == "admin":
        # Admin sees stores they own + their current store
        stores = await db.stores.find(
            {"$or": [{"owner_id": user["id"]}, {"id": user.get("store_id", "")}]},
            {"_id": 0},
        ).to_list(50)
    else:
        # Non-admin sees only their current store
        stores = await db.stores.find({"id": user.get("store_id", "")}, {"_id": 0}).to_list(50)
    return stores


@api_router.post("/stores")
async def create_store(payload: StoreCreate, user: dict = Depends(require_role("admin"))):
    s = Store(**payload.model_dump(), owner_id=user["id"])
    await db.stores.insert_one(s.model_dump())
    return s.model_dump()


@api_router.put("/stores/{sid}")
async def update_store(sid: str, payload: StoreCreate, user: dict = Depends(require_role("admin"))):
    # Only the owner OR a user in that store (admin) can edit
    store = await db.stores.find_one({"id": sid}, {"_id": 0})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    if store.get("owner_id") != user["id"] and store["id"] != user.get("store_id"):
        raise HTTPException(status_code=403, detail="Not your store")
    await db.stores.update_one({"id": sid}, {"$set": payload.model_dump()})
    return await db.stores.find_one({"id": sid}, {"_id": 0})


@api_router.post("/stores/switch")
async def switch_store(payload: StoreSwitch, response: Response, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can switch stores")
    store = await db.stores.find_one({"id": payload.store_id, "owner_id": user["id"]}, {"_id": 0})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found or not yours")
    await db.users.update_one({"id": user["id"]}, {"$set": {"store_id": payload.store_id}})
    # Reissue token with new store_id
    at = create_access_token(user["id"], user["email"], user["role"], payload.store_id)
    rt = create_refresh_token(user["id"])
    set_auth_cookies(response, at, rt)
    return {"store_id": payload.store_id, "token": at, "store": store}


# -----------------------------------------------------------------------------
# Products
# -----------------------------------------------------------------------------
@api_router.get("/products")
async def list_products(
    user: dict = Depends(get_current_user),
    q: Optional[str] = None,
    category: Optional[str] = None,
    low_stock: Optional[bool] = False,
):
    query = {"store_id": user["store_id"]}
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"sku": {"$regex": q, "$options": "i"}},
            {"barcode": {"$regex": q, "$options": "i"}},
        ]
    if category and category != "all":
        query["category"] = category
    items = await db.products.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    if low_stock:
        items = [p for p in items if p.get("stock_qty", 0) <= p.get("low_stock_threshold", 0)]
    return items


@api_router.post("/products")
async def create_product(payload: ProductCreate, user: dict = Depends(require_role("admin", "manager"))):
    existing = await db.products.find_one({"sku": payload.sku, "store_id": user["store_id"]})
    if existing:
        raise HTTPException(status_code=400, detail="SKU already exists")
    product = Product(**payload.model_dump())
    doc = product.model_dump()
    doc["store_id"] = user["store_id"]
    await db.products.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.get("/products/barcode/{barcode}")
async def product_by_barcode(barcode: str, user: dict = Depends(get_current_user)):
    p = await db.products.find_one({"barcode": barcode, "store_id": user["store_id"]}, {"_id": 0})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found for this barcode")
    return p


# -----------------------------------------------------------------------------
# Inventory CSV Import / Export
# (Must be declared BEFORE /products/{pid} so the path matches correctly)
# -----------------------------------------------------------------------------
CSV_COLUMNS = [
    "name", "sku", "barcode", "category", "sub_category", "unit",
    "purchase_price", "sale_price", "gst_percent",
    "stock_qty", "low_stock_threshold", "description",
]


@api_router.get("/products/export")
async def export_products_csv(user: dict = Depends(get_current_user)):
    products = await db.products.find({"store_id": user["store_id"]}, {"_id": 0}).sort("created_at", -1).to_list(5000)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for p in products:
        writer.writerow({c: p.get(c, "") for c in CSV_COLUMNS})
    buf.seek(0)
    filename = f"kkp-inventory-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@api_router.get("/products/template")
async def products_csv_template(user: dict = Depends(get_current_user)):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerow({
        "name": "Cotton Saree - Floral", "sku": "TEX-SAR-101", "barcode": "8901234500999",
        "category": "Textiles", "sub_category": "Sarees", "unit": "pcs",
        "purchase_price": 450, "sale_price": 799, "gst_percent": 5,
        "stock_qty": 25, "low_stock_threshold": 5,
        "description": "Soft cotton saree with floral print",
    })
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="kkp-inventory-template.csv"'},
    )


def _coerce_float(value, default=0.0):
    try:
        return float(str(value).strip()) if str(value).strip() != "" else default
    except (ValueError, TypeError):
        return default


def _diff_fields(existing: dict, new_doc: dict, fields: list) -> list:
    """Returns list of {field, old, new} for changed fields only."""
    changes = []
    for f in fields:
        old_v = existing.get(f, "")
        new_v = new_doc.get(f, "")
        # Compare strings to avoid 5 vs 5.0 issues for numeric fields
        if str(old_v) != str(new_v):
            changes.append({"field": f, "old": old_v, "new": new_v})
    return changes


@api_router.post("/products/import")
async def import_products_csv(
    file: UploadFile = File(...),
    dry_run: bool = False,
    user: dict = Depends(require_role("admin", "manager")),
):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file")
    content_bytes = await file.read()
    try:
        content = content_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            content = content_bytes.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Could not decode file (use UTF-8)")

    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames or "sku" not in [c.strip().lower() for c in reader.fieldnames]:
        raise HTTPException(status_code=400, detail="CSV must include a 'sku' column. Download the template for the correct format.")

    diff_fields = ["name", "barcode", "category", "sub_category", "unit",
                   "purchase_price", "sale_price", "gst_percent",
                   "stock_qty", "low_stock_threshold", "description"]

    created = 0
    updated = 0
    skipped = 0
    errors: list[dict] = []
    preview_rows: list[dict] = []
    row_num = 1  # header is row 1

    for raw in reader:
        row_num += 1
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        sku = row.get("sku", "")
        name = row.get("name", "")
        if not sku or not name:
            skipped += 1
            err = "Missing required field 'sku' or 'name'"
            errors.append({"row": row_num, "error": err})
            preview_rows.append({"row": row_num, "key": sku or "(blank)", "action": "skip", "error": err})
            continue

        doc = {
            "name": name,
            "sku": sku,
            "barcode": row.get("barcode", ""),
            "category": row.get("category", "Textiles") or "Textiles",
            "sub_category": row.get("sub_category", ""),
            "unit": row.get("unit", "pcs") or "pcs",
            "purchase_price": _coerce_float(row.get("purchase_price"), 0),
            "sale_price": _coerce_float(row.get("sale_price"), 0),
            "gst_percent": _coerce_float(row.get("gst_percent"), 5),
            "stock_qty": _coerce_float(row.get("stock_qty"), 0),
            "low_stock_threshold": _coerce_float(row.get("low_stock_threshold"), 5),
            "description": row.get("description", ""),
            "store_id": user["store_id"],
            "updated_at": now_iso(),
        }

        existing = await db.products.find_one({"sku": sku, "store_id": user["store_id"]})
        try:
            if existing:
                changes = _diff_fields(existing, doc, diff_fields)
                preview_rows.append({"row": row_num, "key": sku, "action": "update", "changes": changes})
                updated += 1
                if not dry_run:
                    await db.products.update_one({"id": existing["id"]}, {"$set": doc})
            else:
                preview_rows.append({
                    "row": row_num, "key": sku, "action": "create",
                    "changes": [{"field": f, "old": "", "new": doc.get(f, "")} for f in diff_fields if doc.get(f, "") != ""],
                })
                created += 1
                if not dry_run:
                    doc["id"] = str(uuid.uuid4())
                    doc["created_at"] = now_iso()
                    await db.products.insert_one(doc)
        except Exception as e:
            skipped += 1
            errors.append({"row": row_num, "sku": sku, "error": str(e)})
            preview_rows.append({"row": row_num, "key": sku, "action": "skip", "error": str(e)})

    return {
        "dry_run": dry_run,
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "errors": errors[:50],
        "rows": preview_rows[:300] if dry_run else [],
        "total_processed": created + updated + skipped,
    }


@api_router.get("/products/{pid}")
async def get_product(pid: str, user: dict = Depends(get_current_user)):
    p = await db.products.find_one({"id": pid, "store_id": user["store_id"]}, {"_id": 0})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    return p


@api_router.put("/products/{pid}")
async def update_product(pid: str, payload: ProductCreate, user: dict = Depends(require_role("admin", "manager"))):
    update = payload.model_dump()
    update["updated_at"] = now_iso()
    res = await db.products.update_one({"id": pid, "store_id": user["store_id"]}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return await db.products.find_one({"id": pid}, {"_id": 0})


@api_router.delete("/products/{pid}")
async def delete_product(pid: str, user: dict = Depends(require_role("admin", "manager"))):
    res = await db.products.delete_one({"id": pid, "store_id": user["store_id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Deleted"}


# -----------------------------------------------------------------------------
# Customers
# -----------------------------------------------------------------------------
@api_router.get("/customers")
async def list_customers(user: dict = Depends(get_current_user), q: Optional[str] = None):
    query = {"store_id": user["store_id"]}
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"phone": {"$regex": q, "$options": "i"}},
        ]
    items = await db.customers.find(query, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


@api_router.post("/customers")
async def create_customer(payload: CustomerCreate, user: dict = Depends(get_current_user)):
    c = Customer(**payload.model_dump())
    doc = c.model_dump()
    doc["store_id"] = user["store_id"]
    await db.customers.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/customers/{cid}")
async def update_customer(cid: str, payload: CustomerCreate, user: dict = Depends(get_current_user)):
    res = await db.customers.update_one({"id": cid, "store_id": user["store_id"]}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Customer not found")
    return await db.customers.find_one({"id": cid}, {"_id": 0})


@api_router.delete("/customers/{cid}")
async def delete_customer(cid: str, user: dict = Depends(require_role("admin", "manager"))):
    await db.customers.delete_one({"id": cid, "store_id": user["store_id"]})
    return {"message": "Deleted"}


@api_router.get("/customers/{cid}/history")
async def customer_history(cid: str, user: dict = Depends(get_current_user)):
    customer = await db.customers.find_one({"id": cid, "store_id": user["store_id"]}, {"_id": 0})
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    sales = await db.sales.find(
        {"store_id": user["store_id"], "customer_id": cid},
        {"_id": 0},
    ).sort("created_at", -1).to_list(200)
    total_spent = sum(s.get("grand_total", 0) for s in sales)
    return {
        "customer": customer,
        "sales": sales,
        "stats": {
            "total_orders": len(sales),
            "total_spent": round(total_spent, 2),
            "avg_order_value": round(total_spent / len(sales), 2) if sales else 0,
            "last_visit": sales[0]["created_at"] if sales else None,
        },
    }


# -----------------------------------------------------------------------------
# Customers CSV import/export
# -----------------------------------------------------------------------------
CUSTOMER_CSV_COLUMNS = ["name", "phone", "email", "address", "gstin"]


@api_router.get("/customers/export")
async def export_customers_csv(user: dict = Depends(get_current_user)):
    items = await db.customers.find({"store_id": user["store_id"]}, {"_id": 0}).sort("created_at", -1).to_list(5000)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CUSTOMER_CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for c in items:
        w.writerow({k: c.get(k, "") for k in CUSTOMER_CSV_COLUMNS})
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="kkp-customers-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")}.csv"'},
    )


@api_router.get("/customers/template")
async def customers_csv_template(user: dict = Depends(get_current_user)):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CUSTOMER_CSV_COLUMNS)
    w.writeheader()
    w.writerow({"name": "Priya Sharma", "phone": "9876543210", "email": "priya@example.com", "address": "Chennai", "gstin": ""})
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="kkp-customers-template.csv"'},
    )


@api_router.post("/customers/import")
async def import_customers_csv(
    file: UploadFile = File(...),
    dry_run: bool = False,
    user: dict = Depends(get_current_user),
):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file")
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        content = raw_bytes.decode("latin-1", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames or "name" not in [c.strip().lower() for c in reader.fieldnames]:
        raise HTTPException(status_code=400, detail="CSV must include a 'name' column. Download the template for the correct format.")

    diff_fields = ["name", "phone", "email", "address", "gstin"]
    created = updated = skipped = 0
    errors: list[dict] = []
    preview_rows: list[dict] = []
    row_num = 1
    for raw in reader:
        row_num += 1
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        name = row.get("name", "")
        phone = row.get("phone", "")
        if not name:
            skipped += 1
            errors.append({"row": row_num, "error": "Missing required field 'name'"})
            preview_rows.append({"row": row_num, "key": "(blank)", "action": "skip", "error": "Missing required field 'name'"})
            continue
        doc = {
            "name": name, "phone": phone, "email": row.get("email", ""),
            "address": row.get("address", ""), "gstin": row.get("gstin", ""),
            "store_id": user["store_id"],
        }
        try:
            query = {"store_id": user["store_id"], "name": name, "phone": phone} if phone else {"store_id": user["store_id"], "name": name, "phone": ""}
            existing = await db.customers.find_one(query)
            if existing:
                changes = _diff_fields(existing, doc, diff_fields)
                preview_rows.append({"row": row_num, "key": f"{name} / {phone or '—'}", "action": "update", "changes": changes})
                updated += 1
                if not dry_run:
                    await db.customers.update_one({"id": existing["id"]}, {"$set": doc})
            else:
                preview_rows.append({
                    "row": row_num, "key": f"{name} / {phone or '—'}", "action": "create",
                    "changes": [{"field": f, "old": "", "new": doc.get(f, "")} for f in diff_fields if doc.get(f, "") != ""],
                })
                created += 1
                if not dry_run:
                    doc["id"] = str(uuid.uuid4())
                    doc["created_at"] = now_iso()
                    await db.customers.insert_one(doc)
        except Exception as e:
            skipped += 1
            errors.append({"row": row_num, "error": str(e)})
            preview_rows.append({"row": row_num, "key": name, "action": "skip", "error": str(e)})

    return {
        "dry_run": dry_run,
        "created": created, "updated": updated, "skipped": skipped,
        "errors": errors[:50],
        "rows": preview_rows[:300] if dry_run else [],
        "total_processed": created + updated + skipped,
    }


# -----------------------------------------------------------------------------
# Suppliers
# -----------------------------------------------------------------------------
@api_router.get("/suppliers")
async def list_suppliers(user: dict = Depends(get_current_user), q: Optional[str] = None):
    query = {"store_id": user["store_id"]}
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"phone": {"$regex": q, "$options": "i"}},
        ]
    items = await db.suppliers.find(query, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


@api_router.post("/suppliers")
async def create_supplier(payload: SupplierCreate, user: dict = Depends(require_role("admin", "manager"))):
    s = Supplier(**payload.model_dump())
    doc = s.model_dump()
    doc["store_id"] = user["store_id"]
    await db.suppliers.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/suppliers/{sid}")
async def update_supplier(sid: str, payload: SupplierCreate, user: dict = Depends(require_role("admin", "manager"))):
    res = await db.suppliers.update_one({"id": sid, "store_id": user["store_id"]}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Supplier not found")
    return await db.suppliers.find_one({"id": sid}, {"_id": 0})


@api_router.delete("/suppliers/{sid}")
async def delete_supplier(sid: str, user: dict = Depends(require_role("admin", "manager"))):
    await db.suppliers.delete_one({"id": sid, "store_id": user["store_id"]})
    return {"message": "Deleted"}


# -----------------------------------------------------------------------------
# Suppliers CSV import/export
# -----------------------------------------------------------------------------
SUPPLIER_CSV_COLUMNS = ["name", "contact_person", "phone", "email", "address", "gstin"]


@api_router.get("/suppliers/export")
async def export_suppliers_csv(user: dict = Depends(get_current_user)):
    items = await db.suppliers.find({"store_id": user["store_id"]}, {"_id": 0}).sort("created_at", -1).to_list(5000)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=SUPPLIER_CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for c in items:
        w.writerow({k: c.get(k, "") for k in SUPPLIER_CSV_COLUMNS})
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="kkp-suppliers-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")}.csv"'},
    )


@api_router.get("/suppliers/template")
async def suppliers_csv_template(user: dict = Depends(get_current_user)):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=SUPPLIER_CSV_COLUMNS)
    w.writeheader()
    w.writerow({"name": "Surat Textile Mills", "contact_person": "Mr. Patel", "phone": "9123456780", "email": "sales@surattextile.com", "address": "Surat, Gujarat", "gstin": "24ABCDE1234F1Z5"})
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="kkp-suppliers-template.csv"'},
    )


@api_router.post("/suppliers/import")
async def import_suppliers_csv(
    file: UploadFile = File(...),
    dry_run: bool = False,
    user: dict = Depends(require_role("admin", "manager")),
):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file")
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        content = raw_bytes.decode("latin-1", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames or "name" not in [c.strip().lower() for c in reader.fieldnames]:
        raise HTTPException(status_code=400, detail="CSV must include a 'name' column. Download the template for the correct format.")

    diff_fields = ["name", "contact_person", "phone", "email", "address", "gstin"]
    created = updated = skipped = 0
    errors: list[dict] = []
    preview_rows: list[dict] = []
    row_num = 1
    for raw in reader:
        row_num += 1
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        name = row.get("name", "")
        phone = row.get("phone", "")
        if not name:
            skipped += 1
            errors.append({"row": row_num, "error": "Missing required field 'name'"})
            preview_rows.append({"row": row_num, "key": "(blank)", "action": "skip", "error": "Missing required field 'name'"})
            continue
        doc = {
            "name": name, "contact_person": row.get("contact_person", ""),
            "phone": phone, "email": row.get("email", ""),
            "address": row.get("address", ""), "gstin": row.get("gstin", ""),
            "store_id": user["store_id"],
        }
        try:
            query = {"store_id": user["store_id"], "name": name, "phone": phone} if phone else {"store_id": user["store_id"], "name": name, "phone": ""}
            existing = await db.suppliers.find_one(query)
            if existing:
                changes = _diff_fields(existing, doc, diff_fields)
                preview_rows.append({"row": row_num, "key": f"{name} / {phone or '—'}", "action": "update", "changes": changes})
                updated += 1
                if not dry_run:
                    await db.suppliers.update_one({"id": existing["id"]}, {"$set": doc})
            else:
                preview_rows.append({
                    "row": row_num, "key": f"{name} / {phone or '—'}", "action": "create",
                    "changes": [{"field": f, "old": "", "new": doc.get(f, "")} for f in diff_fields if doc.get(f, "") != ""],
                })
                created += 1
                if not dry_run:
                    doc["id"] = str(uuid.uuid4())
                    doc["created_at"] = now_iso()
                    await db.suppliers.insert_one(doc)
        except Exception as e:
            skipped += 1
            errors.append({"row": row_num, "error": str(e)})
            preview_rows.append({"row": row_num, "key": name, "action": "skip", "error": str(e)})

    return {
        "dry_run": dry_run,
        "created": created, "updated": updated, "skipped": skipped,
        "errors": errors[:50],
        "rows": preview_rows[:300] if dry_run else [],
        "total_processed": created + updated + skipped,
    }


# -----------------------------------------------------------------------------
# Sales / Billing
# -----------------------------------------------------------------------------
def next_invoice_number(seq: int) -> str:
    return f"KKP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{seq:04d}"


@api_router.post("/sales")
async def create_sale(payload: SaleCreate, user: dict = Depends(get_current_user)):
    if not payload.items:
        raise HTTPException(status_code=400, detail="No items in sale")

    # Validate stock and compute totals
    subtotal = 0.0
    tax_total = 0.0
    grand_total = 0.0
    items_to_save = []
    for it in payload.items:
        product = await db.products.find_one({"id": it.product_id, "store_id": user["store_id"]})
        if not product:
            raise HTTPException(status_code=400, detail=f"Product {it.name} not found")
        if product.get("stock_qty", 0) < it.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for {it.name}")
        base = it.unit_price * it.quantity
        after_discount = base - (it.discount or 0)
        tax = after_discount * (it.gst_percent / 100.0)
        line_total = after_discount + tax
        subtotal += after_discount
        tax_total += tax
        grand_total += line_total
        items_to_save.append({
            **it.model_dump(),
            "line_total": round(line_total, 2),
        })

    grand_total = round(grand_total - (payload.discount_total or 0), 2)

    # Generate invoice number from per-store counter
    counter_key = f"invoice:{user['store_id']}"
    counter = await db.counters.find_one_and_update(
        {"_id": counter_key}, {"$inc": {"seq": 1}}, upsert=True, return_document=True,
    )
    seq = counter.get("seq", 1) if counter else 1
    invoice_no = next_invoice_number(seq)

    sale_doc = {
        "id": str(uuid.uuid4()),
        "store_id": user["store_id"],
        "invoice_no": invoice_no,
        "customer_id": payload.customer_id or "",
        "customer_name": payload.customer_name or "Walk-in Customer",
        "items": items_to_save,
        "subtotal": round(subtotal, 2),
        "tax_total": round(tax_total, 2),
        "discount_total": round(payload.discount_total or 0, 2),
        "grand_total": grand_total,
        "payment_method": payload.payment_method,
        "notes": payload.notes or "",
        "created_by": user["id"],
        "created_by_name": user["name"],
        "created_at": now_iso(),
    }
    await db.sales.insert_one(sale_doc)

    # Decrement stock (scoped to store)
    for it in items_to_save:
        await db.products.update_one(
            {"id": it["product_id"], "store_id": user["store_id"]},
            {"$inc": {"stock_qty": -it["quantity"]}, "$set": {"updated_at": now_iso()}},
        )

    sale_doc.pop("_id", None)
    return sale_doc


@api_router.get("/sales")
async def list_sales(user: dict = Depends(get_current_user), limit: int = 100):
    sales = await db.sales.find({"store_id": user["store_id"]}, {"_id": 0}).sort("created_at", -1).to_list(limit)
    return sales


@api_router.get("/sales/{sid}")
async def get_sale(sid: str, user: dict = Depends(get_current_user)):
    sale = await db.sales.find_one({"id": sid, "store_id": user["store_id"]}, {"_id": 0})
    if not sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    return sale


@api_router.get("/sales/{sid}/pdf")
async def get_sale_pdf(sid: str, user: dict = Depends(get_current_user)):
    sale = await db.sales.find_one({"id": sid, "store_id": user["store_id"]}, {"_id": 0})
    if not sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    store = await db.stores.find_one({"id": user["store_id"]}, {"_id": 0}) or {}

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    INDIGO = colors.HexColor("#2E4A7F")
    INK = colors.HexColor("#1C1F26")
    MUTED = colors.HexColor("#5C6370")
    LINE = colors.HexColor("#E2DFD8")

    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, textColor=INK, leading=13)
    bodyR = ParagraphStyle("bodyR", parent=body, alignment=2)  # right

    flow = []

    # Header block: Store + Invoice info
    store_name = store.get("name", "KKP Stores")
    store_lines = [store_name]
    if store.get("address"):
        store_lines.append(store["address"])
    contact = []
    if store.get("phone"):
        contact.append("Phone: " + store["phone"])
    if store.get("gstin"):
        contact.append("GSTIN: " + store["gstin"])
    if contact:
        store_lines.append(" • ".join(contact))
    left_html = (
        f"<font color='#2E4A7F' size='18'><b>{store_name}</b></font><br/>"
        + "<br/>".join(f"<font color='#5C6370' size='9'>{line}</font>" for line in store_lines[1:])
    )
    right_html = (
        "<font color='#5C6370' size='9'>TAX INVOICE</font><br/>"
        f"<font color='#1C1F26' size='14'><b>{sale['invoice_no']}</b></font><br/>"
        f"<font color='#5C6370' size='9'>{datetime.fromisoformat(sale['created_at'].replace('Z','')).strftime('%d %b %Y, %H:%M') if 'T' in sale['created_at'] else sale['created_at']}</font>"
    )
    header_tbl = Table([[Paragraph(left_html, body), Paragraph(right_html, bodyR)]], colWidths=[100 * mm, 70 * mm])
    header_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    flow.append(header_tbl)
    flow.append(Spacer(1, 8 * mm))

    # Bill To
    bill_to_html = (
        "<font color='#5C6370' size='8'>BILL TO</font><br/>"
        f"<font color='#1C1F26' size='11'><b>{sale.get('customer_name', 'Walk-in Customer')}</b></font>"
    )
    payment_html = (
        "<font color='#5C6370' size='8'>PAYMENT METHOD</font><br/>"
        f"<font color='#1C1F26' size='11'><b>{sale.get('payment_method', 'cash').upper()}</b></font>"
    )
    bt = Table([[Paragraph(bill_to_html, body), Paragraph(payment_html, bodyR)]], colWidths=[100 * mm, 70 * mm])
    bt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    flow.append(bt)
    flow.append(Spacer(1, 6 * mm))

    # Items table
    rupee = "\u20B9"
    data = [["#", "Item", "Qty", "Rate", "GST%", "Total"]]
    for idx, it in enumerate(sale.get("items", []), 1):
        data.append([
            str(idx),
            it.get("name", ""),
            f"{it.get('quantity', 0):g}",
            f"{rupee}{it.get('unit_price', 0):.2f}",
            f"{it.get('gst_percent', 0):g}%",
            f"{rupee}{it.get('line_total', 0):.2f}",
        ])
    items_tbl = Table(data, colWidths=[10 * mm, 75 * mm, 18 * mm, 25 * mm, 17 * mm, 25 * mm])
    items_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F1ED")),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]))
    flow.append(items_tbl)
    flow.append(Spacer(1, 6 * mm))

    # Totals (right-aligned block)
    totals_rows = [
        ["Subtotal", f"{rupee}{sale.get('subtotal', 0):.2f}"],
        ["GST", f"{rupee}{sale.get('tax_total', 0):.2f}"],
    ]
    if sale.get("discount_total"):
        totals_rows.append(["Discount", f"-{rupee}{sale['discount_total']:.2f}"])
    totals_rows.append(["Grand Total", f"{rupee}{sale.get('grand_total', 0):.2f}"])
    totals_tbl = Table(totals_rows, colWidths=[60 * mm, 30 * mm])
    totals_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -2), 10),
        ("TEXTCOLOR", (0, 0), (-1, -2), MUTED),
        ("FONTSIZE", (0, -1), (-1, -1), 13),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, -1), (-1, -1), INDIGO),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("LINEABOVE", (0, -1), (-1, -1), 0.7, INDIGO),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    wrap = Table([["", totals_tbl]], colWidths=[80 * mm, 90 * mm])
    wrap.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    flow.append(wrap)
    flow.append(Spacer(1, 12 * mm))

    # Footer note
    flow.append(Paragraph(
        f"<font color='#5C6370' size='8'>Generated on {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')} • This is a computer-generated invoice.</font>",
        body,
    ))
    flow.append(Spacer(1, 2 * mm))
    flow.append(Paragraph(
        "<font color='#2E4A7F' size='9'><b>Thank you for shopping with us!</b></font>",
        body,
    ))

    doc.build(flow)
    buf.seek(0)
    filename = f"{sale['invoice_no']}.pdf"
    return StreamingResponse(
        buf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# -----------------------------------------------------------------------------
# Purchases
# -----------------------------------------------------------------------------
@api_router.post("/purchases")
async def create_purchase(payload: PurchaseCreate, user: dict = Depends(require_role("admin", "manager"))):
    if not payload.items:
        raise HTTPException(status_code=400, detail="No items in purchase")
    total = 0.0
    items_to_save = []
    for it in payload.items:
        line_total = it.quantity * it.unit_cost
        total += line_total
        items_to_save.append({**it.model_dump(), "line_total": round(line_total, 2)})

    counter_key = f"purchase:{user['store_id']}"
    counter = await db.counters.find_one_and_update(
        {"_id": counter_key}, {"$inc": {"seq": 1}}, upsert=True, return_document=True,
    )
    seq = counter.get("seq", 1) if counter else 1
    po_no = f"PO-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{seq:04d}"

    doc = {
        "id": str(uuid.uuid4()),
        "store_id": user["store_id"],
        "po_no": po_no,
        "supplier_id": payload.supplier_id,
        "supplier_name": payload.supplier_name,
        "items": items_to_save,
        "total": round(total, 2),
        "notes": payload.notes or "",
        "created_by": user["id"],
        "created_at": now_iso(),
    }
    await db.purchases.insert_one(doc)

    # Increment stock (scoped to store)
    for it in items_to_save:
        await db.products.update_one(
            {"id": it["product_id"], "store_id": user["store_id"]},
            {"$inc": {"stock_qty": it["quantity"]},
             "$set": {"purchase_price": it["unit_cost"], "updated_at": now_iso()}},
        )
    doc.pop("_id", None)
    return doc


@api_router.get("/purchases")
async def list_purchases(user: dict = Depends(get_current_user)):
    items = await db.purchases.find({"store_id": user["store_id"]}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


# -----------------------------------------------------------------------------
# Dashboard & Reports
# -----------------------------------------------------------------------------
@api_router.get("/dashboard/summary")
async def dashboard_summary(user: dict = Depends(get_current_user)):
    store_id = user["store_id"]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sales_today_cursor = db.sales.find({"store_id": store_id, "created_at": {"$gte": today}}, {"_id": 0})
    sales_today = await sales_today_cursor.to_list(1000)
    today_sales_amount = sum(s.get("grand_total", 0) for s in sales_today)
    today_orders = len(sales_today)

    products = await db.products.find({"store_id": store_id}, {"_id": 0}).to_list(2000)
    stock_value = sum(p.get("purchase_price", 0) * p.get("stock_qty", 0) for p in products)
    low_stock = [p for p in products if p.get("stock_qty", 0) <= p.get("low_stock_threshold", 0)]

    customers_count = await db.customers.count_documents({"store_id": store_id})

    # Last 7 days sales for chart
    chart = []
    for i in range(6, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        day_sales = await db.sales.find({"store_id": store_id, "created_at": {"$gte": day, "$lt": day + "T23:59:59"}}, {"_id": 0}).to_list(500)
        chart.append({
            "date": day,
            "label": (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%a"),
            "total": round(sum(s.get("grand_total", 0) for s in day_sales), 2),
            "orders": len(day_sales),
        })

    # Top selling products (scoped to store)
    pipeline = [
        {"$match": {"store_id": store_id}},
        {"$unwind": "$items"},
        {"$group": {"_id": "$items.name", "qty": {"$sum": "$items.quantity"}, "revenue": {"$sum": "$items.line_total"}}},
        {"$sort": {"qty": -1}},
        {"$limit": 5},
    ]
    top_products = []
    async for r in db.sales.aggregate(pipeline):
        top_products.append({"name": r["_id"], "qty": r["qty"], "revenue": round(r["revenue"], 2)})

    return {
        "today_sales_amount": round(today_sales_amount, 2),
        "today_orders": today_orders,
        "stock_value": round(stock_value, 2),
        "low_stock_count": len(low_stock),
        "total_products": len(products),
        "total_customers": customers_count,
        "chart_last_7_days": chart,
        "top_products": top_products,
        "low_stock_items": low_stock[:10],
    }


@api_router.get("/dashboard/rollup")
async def dashboard_rollup(user: dict = Depends(require_role("admin"))):
    """Consolidated KPIs across ALL stores owned by the admin."""
    owned = await db.stores.find({"owner_id": user["id"]}, {"_id": 0}).to_list(50)
    if not owned:
        return {"branches": [], "totals": {"today_sales": 0, "today_orders": 0, "stock_value": 0, "low_stock_count": 0, "total_products": 0, "total_customers": 0}, "chart_last_7_days": []}

    store_ids = [s["id"] for s in owned]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    branches = []
    grand_today_sales = 0.0
    grand_today_orders = 0
    grand_stock_value = 0.0
    grand_low_stock = 0
    grand_products = 0
    grand_customers = 0

    # Per-branch breakdown
    for s in owned:
        sid = s["id"]
        sales_today = await db.sales.find({"store_id": sid, "created_at": {"$gte": today}}, {"_id": 0}).to_list(1000)
        prods = await db.products.find({"store_id": sid}, {"_id": 0}).to_list(2000)
        stock_value = sum(p.get("purchase_price", 0) * p.get("stock_qty", 0) for p in prods)
        low_stock = [p for p in prods if p.get("stock_qty", 0) <= p.get("low_stock_threshold", 0)]
        cust_count = await db.customers.count_documents({"store_id": sid})
        today_amount = sum(x.get("grand_total", 0) for x in sales_today)

        branches.append({
            "id": sid,
            "name": s["name"],
            "today_sales_amount": round(today_amount, 2),
            "today_orders": len(sales_today),
            "stock_value": round(stock_value, 2),
            "low_stock_count": len(low_stock),
            "total_products": len(prods),
            "total_customers": cust_count,
        })
        grand_today_sales += today_amount
        grand_today_orders += len(sales_today)
        grand_stock_value += stock_value
        grand_low_stock += len(low_stock)
        grand_products += len(prods)
        grand_customers += cust_count

    # 7-day combined chart across all stores
    chart = []
    for i in range(6, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        day_sales = await db.sales.find({
            "store_id": {"$in": store_ids},
            "created_at": {"$gte": day, "$lt": day + "T23:59:59"},
        }, {"_id": 0}).to_list(2000)
        chart.append({
            "date": day,
            "label": (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%a"),
            "total": round(sum(s.get("grand_total", 0) for s in day_sales), 2),
            "orders": len(day_sales),
        })

    # Top selling products across all owned stores
    pipeline = [
        {"$match": {"store_id": {"$in": store_ids}}},
        {"$unwind": "$items"},
        {"$group": {"_id": "$items.name", "qty": {"$sum": "$items.quantity"}, "revenue": {"$sum": "$items.line_total"}}},
        {"$sort": {"qty": -1}},
        {"$limit": 5},
    ]
    top_products = []
    async for r in db.sales.aggregate(pipeline):
        top_products.append({"name": r["_id"], "qty": r["qty"], "revenue": round(r["revenue"], 2)})

    return {
        "branches": branches,
        "totals": {
            "today_sales": round(grand_today_sales, 2),
            "today_orders": grand_today_orders,
            "stock_value": round(grand_stock_value, 2),
            "low_stock_count": grand_low_stock,
            "total_products": grand_products,
            "total_customers": grand_customers,
        },
        "chart_last_7_days": chart,
        "top_products": top_products,
    }


@api_router.get("/reports/sales")
async def sales_report(user: dict = Depends(get_current_user), days: int = 30):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    sales = await db.sales.find({"store_id": user["store_id"], "created_at": {"$gte": since}}, {"_id": 0}).to_list(5000)
    total = sum(s.get("grand_total", 0) for s in sales)
    tax = sum(s.get("tax_total", 0) for s in sales)
    return {
        "period_days": days,
        "count": len(sales),
        "total": round(total, 2),
        "tax": round(tax, 2),
        "sales": sales,
    }


@api_router.get("/reports/stock")
async def stock_report(user: dict = Depends(get_current_user)):
    products = await db.products.find({"store_id": user["store_id"]}, {"_id": 0}).to_list(2000)
    total_value = sum(p.get("purchase_price", 0) * p.get("stock_qty", 0) for p in products)
    return {
        "products": products,
        "total_value": round(total_value, 2),
        "out_of_stock": [p for p in products if p.get("stock_qty", 0) <= 0],
        "low_stock": [p for p in products if 0 < p.get("stock_qty", 0) <= p.get("low_stock_threshold", 0)],
    }


# -----------------------------------------------------------------------------
# AI Insights (Claude via emergentintegrations)
# -----------------------------------------------------------------------------
@api_router.post("/ai/insights")
async def ai_insights(payload: AIInsightRequest, user: dict = Depends(get_current_user)):
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI library not available: {e}")

    # Gather store snapshot
    store_id = user["store_id"]
    products = await db.products.find({"store_id": store_id}, {"_id": 0}).to_list(500)
    sales = await db.sales.find({"store_id": store_id}, {"_id": 0}).sort("created_at", -1).to_list(200)

    low_stock = [
        {"name": p["name"], "sku": p["sku"], "stock": p.get("stock_qty", 0), "threshold": p.get("low_stock_threshold", 0)}
        for p in products if p.get("stock_qty", 0) <= p.get("low_stock_threshold", 0)
    ][:15]

    # Top sellers
    sales_count = {}
    for s in sales:
        for it in s.get("items", []):
            sales_count.setdefault(it["name"], {"qty": 0, "revenue": 0})
            sales_count[it["name"]]["qty"] += it.get("quantity", 0)
            sales_count[it["name"]]["revenue"] += it.get("line_total", 0)
    top = sorted(sales_count.items(), key=lambda x: x[1]["qty"], reverse=True)[:8]

    total_revenue = sum(s.get("grand_total", 0) for s in sales)
    total_orders = len(sales)
    avg_order_value = (total_revenue / total_orders) if total_orders else 0

    snapshot = (
        f"Store: KKP Stores (Textile & Home Utility)\n"
        f"Total Products: {len(products)} | Total Orders (recent): {total_orders} | "
        f"Total Revenue (recent): ₹{total_revenue:.2f} | AOV: ₹{avg_order_value:.2f}\n"
        f"Low Stock Items ({len(low_stock)}): {low_stock}\n"
        f"Top Sellers: {[(name, d['qty']) for name, d in top]}\n"
        f"Focus area: {payload.focus}\n"
    )

    system_msg = (
        "You are a retail business analyst for KKP Stores, an Indian textile and home utility shop. "
        "Provide concise, actionable insights in plain English. Use INR (₹) currency. "
        "Structure output with: 1) Key Observations 2) Risks & Opportunities 3) Specific Recommendations (numbered). "
        "Keep it under 250 words, business-focused, and tailored to small-to-medium Indian retailers."
    )

    try:
        chat = LlmChat(
            api_key=os.environ["EMERGENT_LLM_KEY"],
            session_id=f"insights-{user['id']}-{uuid.uuid4()}",
            system_message=system_msg,
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")
        msg = UserMessage(text=f"Analyze this store snapshot and give insights:\n\n{snapshot}")
        response_text = await chat.send_message(msg)
    except Exception as e:
        logger.exception("AI insights failed")
        raise HTTPException(status_code=500, detail=f"AI generation failed: {str(e)}")

    return {
        "insights": response_text,
        "snapshot": {
            "total_products": len(products),
            "total_orders": total_orders,
            "total_revenue": round(total_revenue, 2),
            "avg_order_value": round(avg_order_value, 2),
            "low_stock_count": len(low_stock),
            "top_sellers": [{"name": name, "qty": d["qty"], "revenue": round(d["revenue"], 2)} for name, d in top],
        },
    }


# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@api_router.get("/")
async def root():
    return {"message": "KKP Stores API", "status": "ok"}


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    await db.users.create_index("email", unique=True)
    # Per-store SKU uniqueness
    try:
        await db.products.drop_index("sku_1")
    except Exception:
        pass
    await db.products.create_index([("store_id", 1), ("sku", 1)], unique=True)
    await db.products.create_index("barcode")
    await db.products.create_index("store_id")
    await db.sales.create_index([("store_id", 1), ("created_at", -1)])
    await db.purchases.create_index([("store_id", 1), ("created_at", -1)])
    await db.customers.create_index("store_id")
    await db.suppliers.create_index("store_id")
    await db.stores.create_index("owner_id")

    # Ensure a default store exists
    default_store = await db.stores.find_one({}, {"_id": 0})
    if not default_store:
        # Will be created after admin user is seeded below
        default_store_id = str(uuid.uuid4())
    else:
        default_store_id = default_store["id"]

    # Seed admin user
    admin_email_l = ADMIN_EMAIL.lower()
    existing_admin = await db.users.find_one({"email": admin_email_l})
    if not existing_admin:
        admin_id = str(uuid.uuid4())
        # If no default store yet, create one with this admin as owner
        if not default_store:
            await db.stores.insert_one({
                "id": default_store_id,
                "name": "KKP Stores - Main Branch",
                "address": "Coimbatore, Tamil Nadu",
                "phone": "",
                "gstin": "",
                "owner_id": admin_id,
                "created_at": now_iso(),
            })
        await db.users.insert_one({
            "id": admin_id,
            "name": "Admin",
            "email": admin_email_l,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "role": "admin",
            "store_id": default_store_id,
            "created_at": now_iso(),
        })
        logger.info("Admin user + default store seeded")
    else:
        # Refresh password if env-controlled value changed
        if not verify_password(ADMIN_PASSWORD, existing_admin["password_hash"]):
            await db.users.update_one(
                {"email": admin_email_l},
                {"$set": {"password_hash": hash_password(ADMIN_PASSWORD)}},
            )
            logger.info("Admin password refreshed")
        # Ensure admin has store_id and that store exists
        if not existing_admin.get("store_id"):
            if not default_store:
                await db.stores.insert_one({
                    "id": default_store_id, "name": "KKP Stores - Main Branch",
                    "address": "", "phone": "", "gstin": "",
                    "owner_id": existing_admin["id"], "created_at": now_iso(),
                })
            await db.users.update_one({"id": existing_admin["id"]}, {"$set": {"store_id": default_store_id}})
        else:
            default_store_id = existing_admin["store_id"]

    # Backfill: assign default_store_id to any legacy docs missing it
    for coll in (db.products, db.customers, db.suppliers, db.sales, db.purchases):
        await coll.update_many({"store_id": {"$exists": False}}, {"$set": {"store_id": default_store_id}})

    # Seed demo products if this store has none
    prod_count = await db.products.count_documents({"store_id": default_store_id})
    if prod_count == 0:
        demo = [
            {"name": "Cotton Saree - Floral", "sku": "TEX-SAR-001", "barcode": "8901234500011", "category": "Textiles", "sub_category": "Sarees", "unit": "pcs", "purchase_price": 450, "sale_price": 799, "gst_percent": 5, "stock_qty": 25, "low_stock_threshold": 5},
            {"name": "Silk Saree - Maroon", "sku": "TEX-SAR-002", "barcode": "8901234500028", "category": "Textiles", "sub_category": "Sarees", "unit": "pcs", "purchase_price": 1200, "sale_price": 2499, "gst_percent": 5, "stock_qty": 8, "low_stock_threshold": 3},
            {"name": "Cotton Bedsheet - King", "sku": "TEX-BED-001", "barcode": "8901234500035", "category": "Textiles", "sub_category": "Bedsheets", "unit": "pcs", "purchase_price": 350, "sale_price": 699, "gst_percent": 5, "stock_qty": 40, "low_stock_threshold": 8},
            {"name": "Bath Towel - Premium", "sku": "TEX-TWL-001", "barcode": "8901234500042", "category": "Textiles", "sub_category": "Towels", "unit": "pcs", "purchase_price": 120, "sale_price": 249, "gst_percent": 5, "stock_qty": 60, "low_stock_threshold": 12},
            {"name": "Steel Pressure Cooker 3L", "sku": "HU-COOK-001", "barcode": "8901234500059", "category": "Home Utility", "sub_category": "Cookware", "unit": "pcs", "purchase_price": 850, "sale_price": 1499, "gst_percent": 12, "stock_qty": 15, "low_stock_threshold": 4},
            {"name": "Non-stick Tawa 28cm", "sku": "HU-COOK-002", "barcode": "8901234500066", "category": "Home Utility", "sub_category": "Cookware", "unit": "pcs", "purchase_price": 320, "sale_price": 599, "gst_percent": 12, "stock_qty": 22, "low_stock_threshold": 5},
            {"name": "Storage Container Set (5pc)", "sku": "HU-STOR-001", "barcode": "8901234500073", "category": "Home Utility", "sub_category": "Storage", "unit": "set", "purchase_price": 280, "sale_price": 549, "gst_percent": 18, "stock_qty": 3, "low_stock_threshold": 5},
            {"name": "Plastic Bucket 20L", "sku": "HU-CLEN-001", "barcode": "8901234500080", "category": "Home Utility", "sub_category": "Cleaning", "unit": "pcs", "purchase_price": 95, "sale_price": 199, "gst_percent": 18, "stock_qty": 35, "low_stock_threshold": 10},
            {"name": "Dress Material - Cotton", "sku": "TEX-DRS-001", "barcode": "8901234500097", "category": "Textiles", "sub_category": "Dress Material", "unit": "meter", "purchase_price": 180, "sale_price": 349, "gst_percent": 5, "stock_qty": 120, "low_stock_threshold": 20},
            {"name": "Pillow Cover Pair", "sku": "TEX-PIL-001", "barcode": "8901234500103", "category": "Textiles", "sub_category": "Bedsheets", "unit": "set", "purchase_price": 80, "sale_price": 179, "gst_percent": 5, "stock_qty": 2, "low_stock_threshold": 6},
        ]
        for item in demo:
            p = Product(**item)
            doc = p.model_dump()
            doc["store_id"] = default_store_id
            await db.products.insert_one(doc)
        logger.info("Demo products seeded")

    cust_count = await db.customers.count_documents({"store_id": default_store_id})
    if cust_count == 0:
        demo_cust = [
            {"name": "Walk-in Customer", "phone": "", "address": ""},
            {"name": "Priya Sharma", "phone": "9876543210", "address": "Chennai", "gstin": ""},
            {"name": "Rajesh Kumar", "phone": "9876543211", "address": "Coimbatore"},
        ]
        for d in demo_cust:
            c = Customer(**d)
            doc = c.model_dump()
            doc["store_id"] = default_store_id
            await db.customers.insert_one(doc)

    sup_count = await db.suppliers.count_documents({"store_id": default_store_id})
    if sup_count == 0:
        demo_sup = [
            {"name": "Surat Textile Mills", "contact_person": "Mr. Patel", "phone": "9123456780", "address": "Surat, Gujarat"},
            {"name": "Coimbatore Home Goods", "contact_person": "Mr. Iyer", "phone": "9123456781", "address": "Coimbatore"},
        ]
        for d in demo_sup:
            s = Supplier(**d)
            doc = s.model_dump()
            doc["store_id"] = default_store_id
            await db.suppliers.insert_one(doc)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)
