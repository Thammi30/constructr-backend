"""
Constructr Backend — FastAPI + Supabase
Run: uvicorn main:app --reload
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from supabase import create_client, Client
from passlib.context import CryptContext
import jwt
import uuid
from datetime import datetime, timedelta

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL = "https://ssiatqrwukmbnbpqhzpd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNzaWF0cXJ3dWttYm5icHFoenBkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzk1MjAwNzQsImV4cCI6MjA5NTA5NjA3NH0.WedxRZZgYNtfyAckns-2-7GOhER8B9II7lONK6uWHss"
JWT_SECRET = "constructr-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 72

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Constructr API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://*.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def create_token(user_id: str) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_auth(user_id: Optional[str] = Depends(verify_token)) -> str:
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user_id

# ── Schemas ───────────────────────────────────────────────────────────────────

class SignUpRequest(BaseModel):
    full_name: str
    email: EmailStr
    phone: Optional[str] = None
    password: str
    role: Optional[str] = "buyer"
    company: Optional[str] = None
    location: Optional[str] = None

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class ListingCreate(BaseModel):
    title: str
    category: Optional[str] = None
    equipment_type: Optional[str] = None
    make: Optional[str] = None
    model: Optional[str] = None
    year: Optional[int] = None
    hours: Optional[int] = None
    condition: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    listing_type: Optional[str] = "rent"  # rent / buy / sell
    price: Optional[float] = None
    rental_price: Optional[float] = None
    status: Optional[str] = "active"
    images: Optional[List[str]] = []

class ListingUpdate(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    equipment_type: Optional[str] = None
    make: Optional[str] = None
    model: Optional[str] = None
    year: Optional[int] = None
    hours: Optional[int] = None
    condition: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    listing_type: Optional[str] = None
    price: Optional[float] = None
    rental_price: Optional[float] = None
    status: Optional[str] = None
    images: Optional[List[str]] = None

class EnquiryCreate(BaseModel):
    listing_id: str
    buyer_name: str
    buyer_email: EmailStr
    buyer_phone: Optional[str] = None
    message: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    role: Optional[str] = None

class MessageCreate(BaseModel):
    sender_id: str
    receiver_id: str
    listing_id: Optional[str] = None
    content: str

# ── Auth Routes ───────────────────────────────────────────────────────────────

@app.post("/auth/signup")
async def signup(req: SignUpRequest):
    # Check if email already exists
    existing = supabase.table("users").select("id").eq("email", req.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = pwd_context.hash(req.password)
    user_data = {
        "id": str(uuid.uuid4()),
        "full_name": req.full_name,
        "email": req.email,
        "phone": req.phone,
        "password_hash": hashed,
        "role": req.role,
        "company": req.company,
        "location": req.location,
    }
    result = supabase.table("users").insert(user_data).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create user")

    user = result.data[0]
    token = create_token(user["id"])
    user.pop("password_hash", None)
    return {"token": token, "user": user}


@app.post("/auth/signin")
async def signin(req: SignInRequest):
    result = supabase.table("users").select("*").eq("email", req.email).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = result.data[0]
    if not pwd_context.verify(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(user["id"])
    user.pop("password_hash", None)
    return {"token": token, "user": user}

# ── Listings Routes ───────────────────────────────────────────────────────────

@app.get("/listings")
async def get_listings(
    category: Optional[str] = None,
    listing_type: Optional[str] = None,
    location: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    search: Optional[str] = None,
):
    query = supabase.table("listings").select("*").eq("status", "active")

    if category:
        query = query.eq("category", category)
    if listing_type:
        query = query.eq("listing_type", listing_type)
    if location:
        query = query.ilike("location", f"%{location}%")
    if min_price is not None:
        query = query.gte("price", min_price)
    if max_price is not None:
        query = query.lte("price", max_price)

    result = query.order("created_at", desc=True).execute()
    listings = result.data or []

    # Client-side search fallback (Supabase free tier doesn't have full-text search)
    if search:
        s = search.lower()
        listings = [
            l for l in listings
            if s in (l.get("title") or "").lower()
            or s in (l.get("make") or "").lower()
            or s in (l.get("model") or "").lower()
            or s in (l.get("location") or "").lower()
            or s in (l.get("category") or "").lower()
        ]

    return listings


@app.get("/listings/{listing_id}")
async def get_listing(listing_id: str):
    result = supabase.table("listings").select("*").eq("id", listing_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Listing not found")
    return result.data[0]


@app.post("/listings")
async def create_listing(
    listing: ListingCreate,
    user_id: str = Depends(require_auth),
):
    data = listing.dict()
    data["id"] = str(uuid.uuid4())
    data["user_id"] = user_id
    result = supabase.table("listings").insert(data).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create listing")
    return result.data[0]


@app.put("/listings/{listing_id}")
async def update_listing(
    listing_id: str,
    listing: ListingUpdate,
    user_id: str = Depends(require_auth),
):
    # Verify ownership
    existing = supabase.table("listings").select("user_id").eq("id", listing_id).execute()
    if not existing.data:
        raise HTTPException(status_code=404, detail="Listing not found")
    if existing.data[0]["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    updates = {k: v for k, v in listing.dict().items() if v is not None}
    result = supabase.table("listings").update(updates).eq("id", listing_id).execute()
    return result.data[0]


@app.delete("/listings/{listing_id}")
async def delete_listing(
    listing_id: str,
    user_id: str = Depends(require_auth),
):
    # Verify ownership
    existing = supabase.table("listings").select("user_id").eq("id", listing_id).execute()
    if not existing.data:
        raise HTTPException(status_code=404, detail="Listing not found")
    if existing.data[0]["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    supabase.table("listings").delete().eq("id", listing_id).execute()
    return {"success": True}

# ── Users Routes ──────────────────────────────────────────────────────────────

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    result = supabase.table("users").select("id, full_name, email, phone, role, company, location, created_at").eq("id", user_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="User not found")
    return result.data[0]


@app.put("/users/{user_id}")
async def update_user(
    user_id: str,
    data: UserUpdate,
    current_user_id: str = Depends(require_auth),
):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    updates = {k: v for k, v in data.dict().items() if v is not None}
    result = supabase.table("users").update(updates).eq("id", user_id).execute()
    user = result.data[0]
    user.pop("password_hash", None)
    return user


@app.get("/users/{user_id}/listings")
async def get_user_listings(user_id: str):
    result = supabase.table("listings").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
    return result.data or []

# ── Enquiries Routes ──────────────────────────────────────────────────────────

@app.post("/enquiries")
async def create_enquiry(enquiry: EnquiryCreate):
    data = enquiry.dict()
    data["id"] = str(uuid.uuid4())
    result = supabase.table("enquiries").insert(data).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to submit enquiry")
    return result.data[0]


@app.get("/enquiries")
async def get_enquiries(
    listing_id: Optional[str] = None,
    user_id: str = Depends(require_auth),
):
    query = supabase.table("enquiries").select("*")
    if listing_id:
        query = query.eq("listing_id", listing_id)
    result = query.order("created_at", desc=True).execute()
    return result.data or []

# ── Messages Routes ───────────────────────────────────────────────────────────

@app.post("/messages")
async def send_message(
    msg: MessageCreate,
    user_id: str = Depends(require_auth),
):
    data = msg.dict()
    data["id"] = str(uuid.uuid4())
    result = supabase.table("messages").insert(data).execute()
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to send message")
    return result.data[0]


@app.get("/messages/{user_id}")
async def get_conversations(
    user_id: str,
    current_user: str = Depends(require_auth),
):
    if current_user != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Fetch all messages where user is sender or receiver
    sent = supabase.table("messages").select("*").eq("sender_id", user_id).order("created_at").execute()
    received = supabase.table("messages").select("*").eq("receiver_id", user_id).order("created_at").execute()

    all_messages = (sent.data or []) + (received.data or [])
    all_messages.sort(key=lambda m: m["created_at"])

    # Group into conversations by (other_user_id, listing_id)
    convs = {}
    for msg in all_messages:
        other = msg["receiver_id"] if msg["sender_id"] == user_id else msg["sender_id"]
        listing = msg.get("listing_id")
        key = f"{other}_{listing}"

        if key not in convs:
            convs[key] = {
                "id": key,
                "other_user_id": other,
                "listing_id": listing,
                "messages": [],
                "unread_count": 0,
            }
        convs[key]["messages"].append(msg)

        # Count unread (messages received, not from self)
        if msg["sender_id"] != user_id:
            convs[key]["unread_count"] += 1

    # Enrich with user names and listing titles
    conversations = list(convs.values())
    other_user_ids = list({c["other_user_id"] for c in conversations})
    listing_ids = list({c["listing_id"] for c in conversations if c["listing_id"]})

    # Batch fetch users
    users_map = {}
    if other_user_ids:
        users_res = supabase.table("users").select("id, full_name").in_("id", other_user_ids).execute()
        users_map = {u["id"]: u["full_name"] for u in (users_res.data or [])}

    # Batch fetch listings
    listings_map = {}
    if listing_ids:
        listings_res = supabase.table("listings").select("id, title").in_("id", listing_ids).execute()
        listings_map = {l["id"]: l["title"] for l in (listings_res.data or [])}

    for c in conversations:
        c["other_user_name"] = users_map.get(c["other_user_id"], "Unknown User")
        c["listing_title"] = listings_map.get(c["listing_id"], "") if c["listing_id"] else ""

    # Sort conversations by latest message
    conversations.sort(key=lambda c: c["messages"][-1]["created_at"] if c["messages"] else "", reverse=True)
    return conversations


# ── Health check ─────────────────────────────────────────────────────────────

@app.get("/")
async def health():
    return {"status": "ok", "service": "Constructr API", "version": "1.0.0"}
