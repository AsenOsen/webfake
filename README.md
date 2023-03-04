# What is this project about?

This tool lets you to deploy a server which will act like proxy between browser and some real domain. All requests from client will be passed to the real domain and all URLs in responses will be substituted on fake domain.  

Technically speaking, it is phishing tool, but you can use it for a lot of good reasons:

1. Remove unwanted content from sites
2. Modify site design as you want

I am currently passive working on it, ant it is not production-ready! If you need some assistance, contact me in Telegram - @Asen_17

# TODO

- fix enormously large div-block heights (noon, amazon, google) [something not loading correctly]
- more clever domain substitution [look for encoded domain name in HTML/JS]
- always substitute URL but with original path
- speedup HTTP requests
- make real domain configurable, not hardcoded [best way to do it - through named cookies]
