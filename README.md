# ACME_SSL_Manager
ACME SSL Manager Script


ACME SSL Manager is a Python script that provides a command-line interface for managing SSL certificates using the ACME protocol, particularly designed for Let's Encrypt. It simplifies the process of issuing, renewing, revoking, and installing SSL certificates for your domains.

![Alt text](https://github.com/090ebier/ACME_SSL_Manager/blob/main/ACME_SSL_Manager.py)




Features
Simplified SSL Management: Easily issue, renew, revoke, and install SSL certificates for your domains.
Wildcard Certificate Support: Issue wildcard SSL certificates for your domains with Cloudflare DNS integration.
Informative: Provides detailed information about issued SSL certificates.
User-Friendly Interface: Simple command-line interface to manage SSL certificates.
Requirements
Python 3.x
Colorama: For colored terminal output.
PyFiglet: For printing ASCII banners.

Installation
Clone the repository:

```
git clone https://github.com/090ebier/ACME_SSL_Manager.git
cd ACME_SSL_Manager
```
Install the required dependencies:

 ```
pip install -r requirements.txt
```

Run the script ACME_SSL_Manager.py:
```
python3 ACME_SSL_Manager.py
```

