# ACME SSL Manager


ACME SSL Manager is a Python script that provides a command-line interface for managing SSL certificates using the ACME protocol, particularly designed for Let's Encrypt. It simplifies the process of issuing, renewing, revoking, and installing SSL certificates for your domains.


Features
Simplified SSL Management: Easily issue, renew, revoke, and install SSL certificates for your domains.
Wildcard Certificate Support: Issue wildcard SSL certificates for your domains with Cloudflare DNS integration.
Informative: Provides detailed information about issued SSL certificates.
User-Friendly Interface: Simple command-line interface to manage SSL certificates.



## Menu Options

Here are the options available in ACME SSL Manager and their descriptions:

1. **Update and install Acme:**
   This option updates and upgrades the server, installs curl and socat, installs the Acme Script, and sets the default provider to Let’s Encrypt.

2. **Decode SSL certificate:**
   This option allows you to decode information from an SSL certificate file, such as validity period, issuer, and subject alternative names.

3. **Issue new SSL certificate:**
   This option enables you to issue SSL certificate(s) for the specified domains using Let’s Encrypt.

4. **Revoke SSL certificate:**
   This option revokes SSL certificate(s) for the specified domains using the Acme Script and removes them from the server.

5. **Renew SSL certificate:**
   This option renews SSL certificate(s) for the specified domains using the Acme Script.

6. **Issue wildcard SSL certificate for each domain separately:**
   This option issues wildcard SSL certificate(s) for each specified domain separately using Cloudflare DNS integration.

7. **Issue combined wildcard SSL certificate for multiple domains:**
   This option issues a combined wildcard SSL certificate for multiple specified domains using Cloudflare DNS integration.

8. **Exit:**
   This option exits the program.


Requirements
Python 3.x

## Installation
Clone the repository And Run the script ACME_SSL_Manager.py:

```
git clone https://github.com/090ebier/ACME_SSL_Manager.git
cd ACME_SSL_Manager
python3 ACME_SSL_Manager.py
```

## Preview

![Alt text](https://github.com/090ebier/ACME_SSL_Manager/blob/main/Screenshot.png)
