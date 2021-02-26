# Vultr DNS Authenticator plugin for Certbot

This is a certbot hook script that employs vultr-cli to enable dns challenges with Vultr

## Installation

```
$ npm install certbot-dns-vultr -g
```

## Usage

```
$ sudo certbot certonly \
--agree-tos \
--non-interactive \
--manual \
--manual-auth-hook "certbot-dns-vultr -k {YOUR_VULTR_APIKEY} auth" \
--manual-cleanup-hook "certbot-dns-vultr -k {YOUR_VULTR_APIKEY} cleanup" \
--preferred-challenges dns \
-m "{YOUR_EMAIL_ADDRESS}" \
-d "*.example.com" -d "example.com"
```
