from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
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
    allow_origins=["*"],
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

def verify_shopify_hmac(query_params: dict, secret: str) -> bool:
    """Verify Shopify HMAC signature"""
    if 'hmac' not in query_params:
        return False
    
    hmac_to_verify = query_params.pop('hmac')
    
    # Create sorted query string
    sorted_params = sorted(query_params.items())
    query_string = '&'.join([f"{key}={value}" for key, value in sorted_params])
    
    # Calculate HMAC
    calculated_hmac = hmac.new(
        secret.encode('utf-8'),
        query_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(calculated_hmac, hmac_to_verify)

@app.get("/")
async def root(request: Request):
    """Handle app installation and authentication"""
    query_params = dict(request.query_params)
    shop = query_params.get('shop')
    hmac_param = query_params.get('hmac')
    embedded = query_params.get('embedded', '1')
    
    # If no shop parameter, show basic info
    if not shop:
        return {"message": "QuickInsights.ai Shopify App", "status": "ready"}
    
    # Normalize shop domain
    if not shop.endswith('.myshopify.com'):
        shop = f"{shop}.myshopify.com"
    
    # If there's shop and hmac, verify the request is from Shopify
    if shop and hmac_param:
        # Verify HMAC to ensure request is from Shopify
        params_copy = query_params.copy()
        if verify_shopify_hmac(params_copy, SHOPIFY_API_SECRET):
            # Valid request from Shopify, start OAuth
            return await auth(shop, embedded)
        else:
            raise HTTPException(status_code=400, detail="Invalid request signature")
    
    # If only shop parameter (direct access), start OAuth
    if shop:
        return await auth(shop, embedded)
    
    return {"message": "QuickInsights.ai Shopify App", "status": "ready"}

@app.get("/install")
async def install(shop: str, embedded: str = "1"):
    """Handle direct app installation"""
    return await auth(shop, embedded)

@app.get("/auth")
async def auth(shop: str, embedded: str = "1"):
    """Initiate OAuth flow"""
    if not shop:
        raise HTTPException(status_code=400, detail="Shop parameter is required")
        
    # Normalize shop domain
    if not shop.endswith('.myshopify.com'):
        shop = f"{shop}.myshopify.com"
    
    # Generate and store state for CSRF protection
    state = str(uuid.uuid4())
    oauth_states[state] = shop
    
    # Shopify OAuth parameters
    params = {
        'client_id': SHOPIFY_API_KEY,
        'scope': SHOPIFY_SCOPES,
        'redirect_uri': f"{APP_URL}/auth/callback",
        'state': state,
    }
    
    auth_url = f"https://{shop}/admin/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url=auth_url, status_code=302)

@app.get("/auth/callback")
async def auth_callback(request: Request, session: Session = Depends(get_session)):
    """Handle OAuth callback from Shopify"""
    query_params = dict(request.query_params)
    shop = query_params.get('shop')
    code = query_params.get('code')
    state = query_params.get('state')
    
    if not shop or not code:
        raise HTTPException(status_code=400, detail="Missing shop or code parameters")
    
    # Verify state to prevent CSRF attacks
    if not state or state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid or expired state parameter")
    
    # Verify shop matches state
    if oauth_states[state] != shop:
        raise HTTPException(status_code=400, detail="Shop domain mismatch")
    
    # Clean up state
    del oauth_states[state]
    
    # Verify HMAC signature
    params_for_hmac = query_params.copy()
    if not verify_shopify_hmac(params_for_hmac, SHOPIFY_API_SECRET):
        raise HTTPException(status_code=400, detail="Invalid request signature")
    
    # Exchange authorization code for access token
    token_data = {
        'client_id': SHOPIFY_API_KEY, 
        'client_secret': SHOPIFY_API_SECRET, 
        'code': code
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"https://{shop}/admin/oauth/access_token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Failed to exchange code for token: {response.status_code}"
                )
            
            try:
                token_response = response.json()
            except json.JSONDecodeError:
                # Handle URL-encoded response format
                if 'access_token=' in response.text:
                    parsed = parse_qs(response.text)
                    token_response = {
                        'access_token': parsed.get('access_token', [''])[0], 
                        'scope': parsed.get('scope', [''])[0]
                    }
                else:
                    raise HTTPException(status_code=400, detail="Invalid token response format")
                    
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Network error during token exchange: {str(e)}")
    
    access_token = token_response.get('access_token')
    if not access_token:
        raise HTTPException(status_code=400, detail="No access token received from Shopify")
    
    # Store or update shop data in database
    try:
        existing_shop = session.exec(select(Shop).where(Shop.shop_domain == shop)).first()
        if existing_shop:
            existing_shop.access_token = access_token
            existing_shop.scope = token_response.get('scope', SHOPIFY_SCOPES)
            existing_shop.is_active = True
        else:
            new_shop = Shop(
                shop_domain=shop, 
                access_token=access_token, 
                scope=token_response.get('scope', SHOPIFY_SCOPES),
                is_active=True
            )
            session.add(new_shop)
        session.commit()
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    # Register mandatory webhooks asynchronously
    asyncio.create_task(register_webhooks(shop, access_token))
    
    # Redirect to embedded app - THIS IS THE KEY FIX
    # For embedded apps, redirect to the Shopify admin with the app embedded
    redirect_url = f"https://{shop}/admin/apps/{SHOPIFY_API_KEY}"
    
    return RedirectResponse(url=redirect_url, status_code=302)

@app.get("/app")
async def app_home(request: Request):
    """Main app interface - this is where your embedded app UI goes"""
    shop = request.query_params.get('shop')
    
    if not shop:
        return HTMLResponse("""
        <html>
            <head><title>QuickInsights.ai</title></head>
            <body>
                <h1>Error: Shop parameter missing</h1>
                <p>This app must be accessed through Shopify admin.</p>
            </body>
        </html>
        """, status_code=400)
    
    # Basic embedded app HTML with App Bridge
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>QuickInsights.ai</title>
        <script src="https://unpkg.com/@shopify/app-bridge@3"></script>
        <script src="https://unpkg.com/@shopify/app-bridge-utils@3"></script>
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 20px;
                background-color: #f6f6f7;
            }}
            .container {{
                max-width: 800px;
                margin: 0 auto;
                background: white;
                padding: 24px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                margin-bottom: 32px;
            }}
            .logo {{
                font-size: 24px;
                font-weight: bold;
                color: #202223;
                margin-bottom: 8px;
            }}
            .subtitle {{
                color: #6d7175;
                font-size: 16px;
            }}
            .status {{
                background: #d4f2d4;
                color: #1a7f1a;
                padding: 12px 16px;
                border-radius: 6px;
                margin: 16px 0;
                text-align: center;
            }}
            .feature-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 16px;
                margin-top: 24px;
            }}
            .feature-card {{
                border: 1px solid #e1e3e5;
                border-radius: 6px;
                padding: 16px;
            }}
            .feature-title {{
                font-weight: 600;
                margin-bottom: 8px;
                color: #202223;
            }}
            .feature-desc {{
                color: #6d7175;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🚀 QuickInsights.ai</div>
                <div class="subtitle">AI-Powered Analytics for Your Shopify Store</div>
            </div>
            
            <div class="status">
                ✅ Successfully connected to {shop}
            </div>
            
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-title">Product Analytics</div>
                    <div class="feature-desc">Get insights into your product performance with AI-powered analytics.</div>
                </div>
                <div class="feature-card">
                    <div class="feature-title">Customer Insights</div>
                    <div class="feature-desc">Understand your customers better with advanced segmentation.</div>
                </div>
                <div class="feature-card">
                    <div class="feature-title">Sales Forecasting</div>
                    <div class="feature-desc">Predict future sales trends using machine learning algorithms.</div>
                </div>
                <div class="feature-card">
                    <div class="feature-title">Automated Reporting</div>
                    <div class="feature-desc">Receive weekly reports with actionable business insights.</div>
                </div>
            </div>
        </div>
        
        <script>
            // Initialize Shopify App Bridge
            var AppBridge = window['app-bridge'];
            var createApp = AppBridge.default;
            var app = createApp({{
                apiKey: '{SHOPIFY_API_KEY}',
                shop: '{shop}',
                forceRedirect: true
            }});
            
            // Set up navigation
            var NavigationMenu = AppBridge.NavigationMenu;
            var navigationMenu = NavigationMenu.create(app, {{
                items: [
                    {{
                        id: 'dashboard',
                        label: 'Dashboard',
                        destination: '/app?shop={shop}'
                    }},
                    {{
                        id: 'analytics',
                        label: 'Analytics',
                        destination: '/app/analytics?shop={shop}'
                    }},
                    {{
                        id: 'settings',
                        label: 'Settings', 
                        destination: '/app/settings?shop={shop}'
                    }}
                ]
            }});
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

async def register_webhooks(shop: str, access_token: str):
    """Register mandatory GDPR and app webhooks"""
    mandatory_webhooks = [
        {
            "webhook": {
                "topic": "customers/data_request", 
                "address": f"{APP_URL}/webhooks/customers/data_request", 
                "format": "json"
            }
        },
        {
            "webhook": {
                "topic": "customers/redact", 
                "address": f"{APP_URL}/webhooks/customers/redact", 
                "format": "json"
            }
        },
        {
            "webhook": {
                "topic": "shop/redact", 
                "address": f"{APP_URL}/webhooks/shop/redact", 
                "format": "json"
            }
        },
        {
            "webhook": {
                "topic": "app/uninstalled", 
                "address": f"{APP_URL}/webhooks/app/uninstalled", 
                "format": "json"
            }
        }
    ]
    
    headers = {
        "X-Shopify-Access-Token": access_token, 
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        for webhook_data in mandatory_webhooks:
            try:
                # Check if webhook already exists
                list_response = await client.get(
                    f"https://{shop}/admin/api/2024-07/webhooks.json",
                    headers=headers
                )
                
                if list_response.status_code == 200:
                    existing_webhooks = list_response.json().get('webhooks', [])
                    topic = webhook_data['webhook']['topic']
                    
                    # Skip if webhook already exists for this topic
                    if any(w.get('topic') == topic for w in existing_webhooks):
                        print(f"Webhook already exists for topic: {topic}")
                        continue
                
                # Create the webhook
                create_response = await client.post(
                    f"https://{shop}/admin/api/2024-07/webhooks.json", 
                    headers=headers, 
                    json=webhook_data
                )
                
                if create_response.status_code in [200, 201]:
                    print(f"✅ Successfully registered webhook: {webhook_data['webhook']['topic']}")
                else:
                    print(f"❌ Failed to register webhook {webhook_data['webhook']['topic']}: {create_response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error registering webhook {webhook_data['webhook']['topic']}: {str(e)}")

# Mandatory GDPR webhook endpoints
@app.post("/webhooks/customers/data_request")
async def webhook_customers_data_request(request: Request):
    """Handle customer data request (GDPR)"""
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized webhook request")
    
    try:
        data = json.loads(body) if body else {}
        shop_domain = data.get('shop_domain', 'unknown')
        customer_id = data.get('customer', {}).get('id', 'unknown')
        print(f"📋 Customer data request for shop: {shop_domain}, customer: {customer_id}")
        
        # TODO: Implement actual data export logic here
        # You should collect and return all customer data your app has stored
        
    except Exception as e:
        print(f"❌ Error processing customer data request: {str(e)}")
    
    return {"status": "acknowledged"}

@app.post("/webhooks/customers/redact")
async def webhook_customers_redact(request: Request):
    """Handle customer data redaction (GDPR)"""
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized webhook request")
    
    try:
        data = json.loads(body) if body else {}
        shop_domain = data.get('shop_domain', 'unknown')
        customer_id = data.get('customer', {}).get('id', 'unknown')
        print(f"🗑️ Customer redaction request for shop: {shop_domain}, customer: {customer_id}")
        
        # TODO: Implement actual data deletion logic here
        # You must delete all customer data your app has stored
        
    except Exception as e:
        print(f"❌ Error processing customer redaction: {str(e)}")
    
    return {"status": "acknowledged"}

@app.post("/webhooks/shop/redact")
async def webhook_shop_redact(request: Request, session: Session = Depends(get_session)):
    """Handle shop data redaction (GDPR)"""
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized webhook request")
    
    try:
        data = json.loads(body) if body else {}
        shop_domain = data.get('shop_domain')
        
        if shop_domain:
            # Delete all shop data for GDPR compliance
            shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain)).first()
            if shop:
                session.delete(shop)
                session.commit()
                print(f"🗑️ Shop data deleted for GDPR compliance: {shop_domain}")
            
            # TODO: Delete all other shop-related data your app has stored
            
    except Exception as e:
        session.rollback()
        print(f"❌ Error processing shop redaction: {str(e)}")
    
    return {"status": "acknowledged"}

@app.post("/webhooks/app/uninstalled")
async def webhook_app_uninstalled(request: Request, session: Session = Depends(get_session)):
    """Handle app uninstallation"""
    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    
    if not verify_hmac(body, hmac_header):
        raise HTTPException(status_code=401, detail="Unauthorized webhook request")
    
    try:
        data = json.loads(body) if body else {}
        shop_domain = data.get('domain')
        
        if shop_domain:
            # Mark shop as inactive when app is uninstalled
            shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain)).first()
            if shop:
                shop.is_active = False
                session.commit()
                print(f"📱 App uninstalled for shop: {shop_domain}")
                
    except Exception as e:
        session.rollback()
        print(f"❌ Error processing app uninstall: {str(e)}")
    
    return {"status": "acknowledged"}

# API endpoints for your app to use
@app.get("/api/shop/{shop_domain}")
async def get_shop_info(shop_domain: str, session: Session = Depends(get_session)):
    """Get shop information"""
    shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain, Shop.is_active == True)).first()
    if not shop:
        raise HTTPException(status_code=404, detail="Shop not found or inactive")
    
    headers = {
        "X-Shopify-Access-Token": shop.access_token, 
        "Content-Type": "application/json"
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"https://{shop_domain}/admin/api/2024-07/shop.json", 
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                # Mark shop as inactive if token is invalid
                shop.is_active = False
                session.commit()
                raise HTTPException(status_code=401, detail="Access token expired or invalid")
            else:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch shop data")
                
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Network error: {str(e)}")

@app.get("/api/products/{shop_domain}")
async def get_products(shop_domain: str, limit: int = 50, session: Session = Depends(get_session)):
    """Get shop products"""
    shop = session.exec(select(Shop).where(Shop.shop_domain == shop_domain, Shop.is_active == True)).first()
    if not shop:
        raise HTTPException(status_code=404, detail="Shop not found or inactive")
    
    headers = {
        "X-Shopify-Access-Token": shop.access_token, 
        "Content-Type": "application/json"
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"https://{shop_domain}/admin/api/2024-07/products.json?limit={min(limit, 250)}", 
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                # Mark shop as inactive if token is invalid
                shop.is_active = False
                session.commit()
                raise HTTPException(status_code=401, detail="Access token expired or invalid")
            else:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch products")
                
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Network error: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "quickinsights-shopify-backend",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)