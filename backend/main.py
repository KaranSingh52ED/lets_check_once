from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import SQLModel, Field, create_engine, Session, select
from typing import Optional, Dict
import httpx
import hmac
import hashlib
import base64
import os
import uuid
from urllib.parse import urlencode, quote, parse_qs
import json
import asyncio
from dotenv import load_dotenv

load_dotenv()

class Shop(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    shop_domain: str = Field(unique=True, index=True)
    access_token: str
    scope: str
    is_active: bool = Field(default=True)

# Environment variables
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET")
APP_URL = os.getenv("APP_URL")
DATABASE_URL = os.getenv("DATABASE_URL")
SHOPIFY_SCOPES = "read_products,write_products,read_orders"

# Validate required environment variables
if not all([SHOPIFY_API_KEY, SHOPIFY_API_SECRET, APP_URL, DATABASE_URL]):
    raise ValueError("Missing required environment variables")

engine = create_engine(DATABASE_URL)
SQLModel.metadata.create_all(engine)

# In-memory store for OAuth states (use Redis in production)
oauth_states: Dict[str, str] = {}

def get_session():
    with Session(engine) as session:
        yield session

app = FastAPI()
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

def verify_hmac(data: bytes, hmac_header: str) -> bool:
    if not hmac_header or not SHOPIFY_WEBHOOK_SECRET:
        return False
    try:
        computed_hmac = base64.b64encode(
            hmac.new(SHOPIFY_WEBHOOK_SECRET.encode(), data, hashlib.sha256).digest()
        ).decode()
        return hmac.compare_digest(computed_hmac, hmac_header)
    except Exception:
        return False

@app.get("/")
def root(shop: str = None, hmac: str = None):
    if shop and hmac:
        return auth(shop)
    return {"message": "Shopify App Backend"}

@app.get("/auth")
def auth(shop: str):
    if not shop:
        raise HTTPException(status_code=400, detail="Shop parameter is required")
        
    if not shop.endswith('.myshopify.com'):
        shop = f"{shop}.myshopify.com"
    
    # Generate and store state for CSRF protection
    state = str(uuid.uuid4())
    oauth_states[state] = shop
    
    params = {
        'client_id': SHOPIFY_API_KEY,
        'scope': SHOPIFY_SCOPES,
        'redirect_uri': f"{APP_URL}/auth/callback",
        'state': state
    }
    
    auth_url = f"https://{shop}/admin/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url=auth_url, status_code=302)

@app.get("/auth/callback")
async def auth_callback(request: Request, session: Session = Depends(get_session)):
    query_params = dict(request.query_params)
    shop = query_params.get('shop')
    code = query_params.get('code')
    state = query_params.get('state')
    
    if not shop or not code:
        raise HTTPException(status_code=400, detail="Missing shop or code")
    
    # Verify state to prevent CSRF attacks
    if not state or state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Verify shop matches state
    if oauth_states[state] != shop:
        raise HTTPException(status_code=400, detail="Shop domain mismatch")
    
    # Clean up state
    del oauth_states[state]
    
    # Exchange code for access token
    token_data = {
        'client_id': SHOPIFY_API_KEY, 
        'client_secret': SHOPIFY_API_SECRET, 
        'code': code
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://{shop}/admin/oauth/access_token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail=f"OAuth failed: {response.text}")
            
            try:
                token_response = response.json()
            except json.JSONDecodeError:
                # Handle URL-encoded response
                if 'access_token=' in response.text:
                    parsed = parse_qs(response.text)
                    token_response = {
                        'access_token': parsed.get('access_token', [''])[0], 
                        'scope': parsed.get('scope', [''])[0]
                    }
                else:
                    raise HTTPException(status_code=400, detail="Invalid OAuth response format")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")
    
    if not token_response.get('access_token'):
        raise HTTPException(status_code=400, detail="No access token received")
    
    # Store shop data
    try:
        existing_shop = session.exec(select(Shop).where(Shop.shop_domain == shop)).first()
        if existing_shop:
            existing_shop.access_token = token_response['access_token']
            existing_shop.scope = token_response.get('scope', SHOPIFY_SCOPES)
        else:
            new_shop = Shop(
                shop_domain=shop, 
                access_token=token_response['access_token'], 
                scope=token_response.get('scope', SHOPIFY_SCOPES)
            )
            session.add(new_shop)
        session.commit()
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    # Register webhooks asynchronously
    asyncio.create_task(register_webhooks(shop, token_response['access_token']))
    
    # Generate a user ID for this installation
    user_id = str(uuid.uuid4())
    encoded_user_id = base64.urlsafe_b64encode(user_id.encode()).decode()

    redirect_url = f"https://app.quickinsights.ai/shopify?auth=success&uid={encoded_user_id}&shop={quote(shop)}"

    return RedirectResponse(url=redirect_url, status_code=302)

async def register_webhooks(shop: str, access_token: str):
    webhooks = [
        {"webhook": {"topic": "customers/data_request", "address": f"{APP_URL}/webhooks/customers/data_request", "format": "json"}},
        {"webhook": {"topic": "customers/redact", "address": f"{APP_URL}/webhooks/customers/redact", "format": "json"}},
        {"webhook": {"topic": "shop/redact", "address": f"{APP_URL}/webhooks/shop/redact", "format": "json"}},
        {"webhook": {"topic": "app/uninstalled", "address": f"{APP_URL}/webhooks/app/uninstalled", "format": "json"}}
    ]
    
    headers = {"X-Shopify-Access-Token": access_token, "Content-Type": "application/json"}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for webhook_data in webhooks:
            try:
                response = await client.post(
                    f"https://{shop}/admin/api/2024-07/webhooks.json", 
                    headers=headers, 
                    json=webhook_data
                )
                if response.status_code not in [200, 201]:
                    print(f"Failed to register webhook {webhook_data['webhook']['topic']}: {response.status_code}")
            except Exception as e:
                print(f"Error registering webhook {webhook_data['webhook']['topic']}: {str(e)}")

@app.post("/webhooks/customers/data_request")
async def webhook_customers_data_request(request: Request):
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return {"status": "acknowledged"}

@app.post("/webhooks/customers/redact")
async def webhook_customers_redact(request: Request):
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return {"status": "acknowledged"}

@app.post("/webhooks/shop/redact")
async def webhook_shop_redact(request: Request, session: Session = Depends(get_session)):
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        data = json.loads(body) if body else {}
        shop_domain = data.get('shop_domain')
        if shop_domain:
            shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain)).first()
            if shop:
                session.delete(shop)
                session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error processing shop redact webhook: {str(e)}")
    
    return {"status": "acknowledged"}

@app.post("/webhooks/app/uninstalled")
async def webhook_app_uninstalled(request: Request, session: Session = Depends(get_session)):
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        data = json.loads(body) if body else {}
        shop_domain = data.get('domain')
        if shop_domain:
            shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain)).first()
            if shop:
                shop.is_active = False
                session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error processing app uninstalled webhook: {str(e)}")
    
    return {"status": "acknowledged"}

@app.get("/api/shop/{shop_domain}")
async def get_shop_info(shop_domain: str, session: Session = Depends(get_session)):
    shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain)).first()
    if not shop or not shop.is_active:
        raise HTTPException(status_code=404, detail="Shop not found")
    
    headers = {"X-Shopify-Access-Token": shop.access_token, "Content-Type": "application/json"}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"https://{shop_domain}/admin/api/2024-07/shop.json", headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid access token")
            else:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch shop info")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

@app.get("/api/products/{shop_domain}")
async def get_products(shop_domain: str, session: Session = Depends(get_session)):
    shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain)).first()
    if not shop or not shop.is_active:
        raise HTTPException(status_code=404, detail="Shop not found")
    
    headers = {"X-Shopify-Access-Token": shop.access_token, "Content-Type": "application/json"}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"https://{shop_domain}/admin/api/2024-07/products.json?limit=10", headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid access token")
            else:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch products")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)