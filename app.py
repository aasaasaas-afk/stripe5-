import re
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from flask import Flask, request, jsonify
import nest_asyncio
from concurrent.futures import ThreadPoolExecutor

# Apply nest_asyncio to allow nested event loops
nest_asyncio.apply()

# Initialize Flask app
app = Flask(__name__)

# CMS patterns
CMS_PATTERNS = {
    'Shopify': r'cdn\.shopify\.com|shopify\.js',
    'BigCommerce': r'cdn\.bigcommerce\.com|bigcommerce\.com',
    'Wix': r'static\.parastorage\.com|wix\.com',
    'Squarespace': r'static1\.squarespace\.com|squarespace-cdn\.com',
    'WooCommerce': r'wp-content/plugins/woocommerce/',
    'Magento': r'static/version\d+/frontend/|magento/',
    'PrestaShop': r'prestashop\.js|prestashop/',
    'OpenCart': r'catalog/view/theme|opencart/',
    'Shopify Plus': r'shopify-plus|cdn\.shopifycdn\.net/',
    'Salesforce Commerce Cloud': r'demandware\.edgesuite\.net/',
    'WordPress': r'wp-content|wp-includes/',
    'Joomla': r'media/jui|joomla\.js|media/system/js|joomla\.javascript/',
    'Drupal': r'sites/all/modules|drupal\.js/|sites/default/files|drupal\.settings\.js/',
    'TYPO3': r'typo3temp|typo3/',
    'Concrete5': r'concrete/js|concrete5/',
    'Umbraco': r'umbraco/|umbraco\.config/',
    'Sitecore': r'sitecore/content|sitecore\.js/',
    'Kentico': r'cms/getresource\.ashx|kentico\.js/',
    'Episerver': r'episerver/|episerver\.js/',
    'Custom CMS': r'(?:<meta name="generator" content="([^"]+)")'
}

# Security patterns
SECURITY_PATTERNS = {
    '3D Secure': r'3d_secure|threed_secure|secure_redirect',
}

# Payment gateways list
PAYMENT_GATEWAYS = [
    "PayPal", "Stripe", "Braintree", "Square", "Cybersource", "lemon-squeezy",
    "Authorize.Net", "2Checkout", "Adyen", "Worldpay", "SagePay",
    "Checkout.com", "Bolt", "Eway", "PayFlow", "Payeezy",
    "Paddle", "Mollie", "Viva Wallet", "Rocketgateway", "Rocketgate",
    "Rocket", "Auth.net", "Authnet", "rocketgate.com", "Recurly",
    "Shopify", "WooCommerce", "BigCommerce", "Magento", "Magento Payments",
    "OpenCart", "PrestaShop", "3DCart", "Ecwid", "Shift4Shop",
    "Shopware", "VirtueMart", "CS-Cart", "X-Cart", "LemonStand",
    "Convergepay", "PaySimple", "oceanpayments", "eProcessing",
    "hipay", "cybersourse", "payjunction", "usaepay", "creo",
    "SquareUp", "ebizcharge", "cpay", "Moneris", "cardknox",
    "matt sorra", "Chargify", "Paytrace", "hostedpayments", "securepay",
    "blackbaud", "LawPay", "clover", "cardconnect", "bluepay",
    "fluidpay", "Ebiz", "chasepaymentech", "Auruspay", "sagepayments",
    "paycomet", "geomerchant", "realexpayments", "Razorpay",
    "Apple Pay", "Google Pay", "Samsung Pay", "Cash App",
    "Revolut", "Zelle", "Alipay", "WeChat Pay", "PayPay", "Line Pay",
    "Skrill", "Neteller", "WebMoney", "Payoneer", "Paysafe",
    "Payeer", "GrabPay", "PayMaya", "MoMo", "TrueMoney",
    "Touch n Go", "GoPay", "JKOPay", "EasyPaisa",
    "Paytm", "UPI", "PayU", "PayUBiz", "PayUMoney", "CCAvenue",
    "Mercado Pago", "PagSeguro", "Yandex.Checkout", "PayFort", "MyFatoorah",
    "Kushki", "RuPay", "BharatPe", "Midtrans", "MOLPay",
    "iPay88", "KakaoPay", "Toss Payments", "NaverPay",
    "Bizum", "Culqi", "Pagar.me", "Rapyd", "PayKun", "Instamojo",
    "PhonePe", "BharatQR", "Freecharge", "Mobikwik", "BillDesk",
    "Citrus Pay", "RazorpayX", "Cashfree",
    "Klarna", "Affirm", "Afterpay",
    "Splitit", "Perpay", "Quadpay", "Laybuy", "Openpay",
    "Cashalo", "Hoolah", "Pine Labs", "ChargeAfter",
    "BitPay", "Coinbase Commerce", "CoinGate", "CoinPayments", "Crypto.com Pay",
    "BTCPay Server", "NOWPayments", "OpenNode", "Utrust", "MoonPay",
    "Binance Pay", "CoinsPaid", "BitGo", "Flexa",
    "ACI Worldwide", "Bank of America Merchant Services",
    "JP Morgan Payment Services", "Wells Fargo Payment Solutions",
    "Deutsche Bank Payments", "Barclaycard", "American Express Payment Gateway",
    "Discover Network", "UnionPay", "JCB Payment Gateway",
]

# --- Shared aiohttp session ---
session: aiohttp.ClientSession = None

async def init_session():
    global session
    if session is None or session.closed:
        session = aiohttp.ClientSession()

async def close_session():
    global session
    if session and not session.closed:
        await session.close()

# --- Fetch site ---
async def fetch_site(url: str):
    await init_session()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc

    headers = {
        "authority": domain,
        "scheme": "https",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "max-age=0",
        "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/140.0.0.0 Mobile Safari/537.36",
    }

    try:
        async with session.get(url, headers=headers, timeout=15) as resp:
            text = await resp.text()
            return resp.status, text, resp.headers
    except Exception:
        return None, None, None

# --- Detection functions ---
def detect_cms(html: str):
    for cms, pattern in CMS_PATTERNS.items():
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            if cms == 'Custom CMS':
                return match.group(1) or "Custom CMS"
            return cms
    return "Unknown"

def detect_security(html: str):
    patterns_3ds = [
        r'3d\s*secure',
        r'verified\s*by\s*visa',
        r'mastercard\s*securecode',
        r'american\s*express\s*safekey',
        r'3ds',
        r'3ds2',
        r'acsurl',
        r'pareq',
        r'three-domain-secure',
        r'secure_redirect',
    ]
    for pattern in patterns_3ds:
        if re.search(pattern, html, re.IGNORECASE):
            return "3D Secure Detected"
    return "2D (No 3D Secure Found)"

def detect_gateways(html: str):
    detected = []
    for gateway in PAYMENT_GATEWAYS:
        # Use word boundaries to avoid partial matches (e.g., "PayU" in "PayUmoney")
        pattern = r'\b' + re.escape(gateway) + r'\b'
        if re.search(pattern, html, re.IGNORECASE):
            detected.append(gateway)
    return detected if detected else []

def detect_captcha(html: str):
    html_lower = html.lower()
    if "hcaptcha" in html_lower:
        return "hCaptcha Detected"
    elif "recaptcha" in html_lower or "g-recaptcha" in html_lower:
        return "reCAPTCHA Detected"
    elif "captcha" in html_lower:
        return "Generic Captcha Detected"
    return "No Captcha Detected"

def detect_cloudflare(html: str, headers=None, status=None):
    if headers is None:
        headers = {}
    lower_keys = [k.lower() for k in headers.keys()]
    server = headers.get('Server', '').lower()
    # Check for Cloudflare presence (CDN or protection)
    cloudflare_indicators = [
        r'cloudflare',
        r'cf-ray',
        r'cf-cache-status',
        r'cf-browser-verification',
        r'__cfduid',
        r'cf_chl_',
        r'checking your browser',
        r'enable javascript and cookies',
        r'ray id',
        r'ddos protection by cloudflare',
    ]
    # Check headers for Cloudflare signatures
    if 'cf-ray' in lower_keys or 'cloudflare' in server or 'cf-cache-status' in lower_keys:
        # Parse HTML to check for verification/challenge page
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip().lower() if soup.title else ''
        challenge_indicators = [
            "just a moment",
            "attention required",
            "checking your browser",
            "enable javascript and cookies to continue",
            "ddos protection by cloudflare",
            "please wait while we verify",
        ]
        # Check for challenge page indicators
        if any(indicator in title for indicator in challenge_indicators):
            return "Cloudflare Verification Detected"
        if any(re.search(pattern, html, re.IGNORECASE) for pattern in cloudflare_indicators):
            return "Cloudflare Verification Detected"
        if status in (403, 503) and 'cloudflare' in html.lower():
            return "Cloudflare Verification Detected"
        return "Cloudflare Present (No Verification)"
    return "None"

def detect_graphql(html: str):
    if re.search(r'/graphql|graphqlendpoint|apollo-client|query\s*\{|mutation\s*\{', html, re.IGNORECASE):
        return "GraphQL Detected"
    return "No GraphQL Detected"

# --- Worker for background scanning ---
async def scan_site(url: str):
    status, html, headers = await fetch_site(url)
    
    if not html:
        return {
            "success": False,
            "error": f"Cannot access {url}"
        }

    cms = detect_cms(html)
    security = detect_security(html)
    gateways = detect_gateways(html)
    captcha = detect_captcha(html)
    cloudflare = detect_cloudflare(html, headers=headers, status=status)
    graphql = detect_graphql(html)

    return {
        "success": True,
        "url": url,
        "cms": cms,
        "gateways": gateways,
        "captcha": captcha,
        "cloudflare": cloudflare,
        "security": security,
        "graphql": graphql
    }

# --- API endpoint ---
@app.route('/gateway', methods=['GET'])
def gateway():
    url = request.args.get('url')
    
    if not url:
        return jsonify({
            "success": False,
            "error": "URL parameter is required"
        }), 400
    
    # Run the async function in the event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(scan_site(url))
        return jsonify(result)
    finally:
        loop.close()

# --- Health check endpoint ---
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})

# --- Main function ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
