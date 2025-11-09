import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

# -----------------------------------------------------------------------------
# Auth & Security config
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60  # 1 day

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# -----------------------------------------------------------------------------
# Pydantic models (request/response)
# -----------------------------------------------------------------------------
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    avatar_color: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic

class TaskIn(BaseModel):
    title: str
    notes: Optional[str] = None
    date: str  # YYYY-MM-DD
    time: Optional[str] = None  # HH:MM
    priority: int = 2
    tags: Optional[List[str]] = []

class TaskOut(BaseModel):
    id: str
    title: str
    notes: Optional[str]
    date: str
    time: Optional[str]
    priority: int
    completed: bool
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class TaskPatch(BaseModel):
    title: Optional[str] = None
    notes: Optional[str] = None
    date: Optional[str] = None
    time: Optional[str] = None
    priority: Optional[int] = None
    completed: Optional[bool] = None
    tags: Optional[List[str]] = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
from bson import ObjectId

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_doc = db["authuser"].find_one({"_id": ObjectId(user_id)})
    if not user_doc:
        raise credentials_exception
    return {
        "id": str(user_doc["_id"]),
        "name": user_doc.get("name"),
        "email": user_doc.get("email"),
        "avatar_color": user_doc.get("avatar_color", "#6366f1"),
    }


# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = FastAPI(title="Daily Task Manager API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "Daily Task Manager API running"}


# -----------------------------------------------------------------------------
# Auth routes
# -----------------------------------------------------------------------------
@app.post("/auth/register", response_model=Token)
def register(user: UserCreate):
    # Ensure unique email
    existing = db["authuser"].find_one({"email": user.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "name": user.name.strip(),
        "email": user.email.lower(),
        "hashed_password": hash_password(user.password),
        "avatar_color": "#6366f1",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res_id = db["authuser"].insert_one(user_doc).inserted_id
    access_token = create_access_token({"sub": str(res_id), "email": user.email})
    public = UserPublic(id=str(res_id), name=user_doc["name"], email=user_doc["email"], avatar_color=user_doc["avatar_color"])
    return Token(access_token=access_token, user=public)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # OAuth2PasswordRequestForm uses fields: username, password
    user_doc = db["authuser"].find_one({"email": form_data.username.lower()})
    if not user_doc or not verify_password(form_data.password, user_doc.get("hashed_password", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token({"sub": str(user_doc["_id"]), "email": user_doc["email"]})
    public = UserPublic(id=str(user_doc["_id"]), name=user_doc.get("name", ""), email=user_doc.get("email", ""), avatar_color=user_doc.get("avatar_color", "#6366f1"))
    return Token(access_token=access_token, user=public)


@app.get("/me", response_model=UserPublic)
def me(current_user: dict = Depends(get_current_user)):
    return UserPublic(**current_user)


# -----------------------------------------------------------------------------
# Task routes
# -----------------------------------------------------------------------------
@app.get("/tasks", response_model=List[TaskOut])
def list_tasks(start: Optional[str] = None, end: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {"user_id": str(current_user["id"])}
    if start and end:
        query.update({"date": {"$gte": start, "$lte": end}})
    elif start:
        query.update({"date": {"$gte": start}})
    elif end:
        query.update({"date": {"$lte": end}})

    docs = db["task"].find(query).sort([("date", 1), ("time", 1)])
    results = []
    for d in docs:
        results.append(TaskOut(
            id=str(d["_id"]),
            title=d.get("title"),
            notes=d.get("notes"),
            date=d.get("date"),
            time=d.get("time"),
            priority=d.get("priority", 2),
            completed=d.get("completed", False),
            tags=d.get("tags", []),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        ))
    return results


@app.post("/tasks", response_model=TaskOut, status_code=201)
def create_task(task: TaskIn, current_user: dict = Depends(get_current_user)):
    doc = task.model_dump()
    doc.update({
        "user_id": str(current_user["id"]),
        "completed": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    inserted_id = db["task"].insert_one(doc).inserted_id
    return TaskOut(
        id=str(inserted_id),
        title=doc["title"],
        notes=doc.get("notes"),
        date=doc["date"],
        time=doc.get("time"),
        priority=doc.get("priority", 2),
        completed=doc.get("completed", False),
        tags=doc.get("tags", []),
        created_at=doc.get("created_at"),
        updated_at=doc.get("updated_at"),
    )


@app.patch("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: str, patch: TaskPatch, current_user: dict = Depends(get_current_user)):
    from fastapi.encoders import jsonable_encoder
    updates = {k: v for k, v in patch.model_dump(exclude_unset=True).items()}
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")

    # Ensure only the owner can modify
    q = {"_id": ObjectId(task_id), "user_id": str(current_user["id"])}
    updates["updated_at"] = datetime.now(timezone.utc)
    res = db["task"].update_one(q, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")

    d = db["task"].find_one({"_id": ObjectId(task_id)})
    return TaskOut(
        id=str(d["_id"]),
        title=d.get("title"),
        notes=d.get("notes"),
        date=d.get("date"),
        time=d.get("time"),
        priority=d.get("priority", 2),
        completed=d.get("completed", False),
        tags=d.get("tags", []),
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
    )


@app.delete("/tasks/{task_id}", status_code=204)
def delete_task(task_id: str, current_user: dict = Depends(get_current_user)):
    q = {"_id": ObjectId(task_id), "user_id": str(current_user["id"])}
    res = db["task"].delete_one(q)
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
