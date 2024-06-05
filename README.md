# ACME_SSL_Manager
ACME SSL Manager Script


ACME SSL Manager is a Python script that provides a command-line interface for managing SSL certificates using the ACME protocol, particularly designed for Let's Encrypt. It simplifies the process of issuing, renewing, revoking, and installing SSL certificates for your domains.

![Alt text](https://github.com/090ebier/ACME_SSL_Manager/blob/main/ACME_SSL_Manager_Sreenshot.png)




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


## Command Reference

Here are the commands available in ACME SSL Manager along with their descriptions:

- `update_upgrade_server`: Update and upgrade the server.
  Description: This command updates and upgrades the server by running `apt update && apt upgrade -y`.

- `install_packages`: Install curl and socat.
  Description: This command installs the necessary packages curl and socat using `apt install curl socat -y`.

- `install_acme_script`: Install Acme Script.
  Description: This command installs the Acme Script by downloading it from the internet and executing it using `curl https://get.acme.sh | sh`.

- `set_default_ca`: Set the default provider to Let’s Encrypt.
  Description: This command sets the default certificate authority to Let’s Encrypt using the Acme Script.

- `register_account(email)`: Register an account with the specified email address.
  Description: This command registers an account with the specified email address for use with Let’s Encrypt.

- `issue_certificate(domains)`: Issue SSL certificate(s) for the specified domains.
  Description: This command issues SSL certificate(s) for the specified domains using Let’s Encrypt.

- `revoke_certificate(domains)`: Revoke SSL certificate(s) for the specified domains.
  Description: This command revokes SSL certificate(s) for the specified domains using the Acme Script.

- `renew_certificate(domains)`: Renew SSL certificate(s) for the specified domains.
  Description: This command renews SSL certificate(s) for the specified domains using the Acme Script.

- `issue_wildcard_certificate(domains, email, api_key)`: Issue wildcard SSL certificate(s) for the specified domains using Cloudflare DNS integration.
  Description: This command issues wildcard SSL certificate(s) for the specified domains using Cloudflare DNS integration.

- `install_combined_certificate(domain)`: Install combined wildcard SSL certificate for the specified domain.
  Description: This command installs combined wildcard SSL certificate for the specified domain using the Acme Script.

- `list_domains()`: List available domains.
  Description: This command lists the available domains for which SSL certificates have been issued.

- `select_domains(domains)`: Select domains from the available list.
  Description: This command allows the user to select domains from the list of available domains.

- `decode_certificate_info(cert_file)`: Decode information from the specified SSL certificate file.
  Description: This command decodes information from the specified SSL certificate file using the `openssl x509` command.

- `display_certificate_info(domain)`: Display information of the SSL certificate for the specified domain.
  Description: This command displays information of the SSL certificate for the specified domain, such as validity period, issuer, and subject alternative names.


Run the script ACME_SSL_Manager.py:
```
python3 ACME_SSL_Manager.py
```

