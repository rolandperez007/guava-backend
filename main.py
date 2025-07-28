from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
import time

app = FastAPI()

# -------------------- Models --------------------
class SubscriptionLevel(BaseModel):
    tier: str
    level: int
    price: float
    listings_limit: int
    auto_pushups: bool
    area_specialist: bool
    homepage_logo: bool

class User(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# -------------------- In-Memory DB Simulation --------------------
subscriptions = [
    SubscriptionLevel(tier="Bronze", level=1, price=10000.00, listings_limit=5, auto_pushups=False, area_specialist=False, homepage_logo=False),
    SubscriptionLevel(tier="Bronze", level=2, price=12000.00, listings_limit=10, auto_pushups=False, area_specialist=True, homepage_logo=False),
    SubscriptionLevel(tier="Bronze", level=3, price=15000.00, listings_limit=15, auto_pushups=True, area_specialist=True, homepage_logo=False),
    SubscriptionLevel(tier="Silver", level=1, price=20000.00, listings_limit=25, auto_pushups=True, area_specialist=True, homepage_logo=True),
    SubscriptionLevel(tier="Silver", level=2, price=25000.00, listings_limit=35, auto_pushups=True, area_specialist=True, homepage_logo=True),
    SubscriptionLevel(tier="Silver", level=3, price=35000.00, listings_limit=45, auto_pushups=True, area_specialist=True, homepage_logo=True),
    SubscriptionLevel(tier="Gold", level=1, price=60000.00, listings_limit=60, auto_pushups=True, area_specialist=True, homepage_logo=True),
    SubscriptionLevel(tier="Gold", level=2, price=75000.00, listings_limit=75, auto_pushups=True, area_specialist=True, homepage_logo=True),
    SubscriptionLevel(tier="Gold", level=3, price=80000.00, listings_limit=100, auto_pushups=True, area_specialist=True, homepage_logo=True),
]

users_db = {}

# -------------------- Security --------------------
SECRET_KEY = "your-super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    user = users_db.get(email)
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# -------------------- Routes --------------------
@app.get("/dashboard")
def dashboard():
    return {"message": "Welcome to the Guava App Property Finder Backend"}

@app.get("/subscriptions")
def get_subscriptions():
    return subscriptions

@app.post("/register")
def register(user: User):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    users_db[user.email] = {
        "email": user.email,
        "password": get_password_hash(user.password)
    }
    return {"message": "User registered successfully"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token(data={"sub": user['email']})
    return {"access_token": token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None or email not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def start_simulation(plan_id=None):
    time.sleep(1)
    return {
        "simulation_id": "sim-ABC123",
        "message": "3D simulation started",
        "plan_id": plan_id or "default-plan"
    }

@app.post("/start-simulation")
async def simulate(request: Request):
    data = await request.json()
    plan_id = data.get('plan_id')
    result = start_simulation(plan_id)
    return {"status": "started", "details": result}