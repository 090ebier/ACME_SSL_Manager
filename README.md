# ACME SSL Manager

**ACME SSL Manager** is a Python script that provides a user-friendly command-line interface for managing SSL certificates using the ACME protocol, specifically designed for Let's Encrypt. It simplifies the process of issuing, renewing, revoking, and installing SSL certificates for your domains, including support for wildcard certificates with manual DNS verification.

## Features
- **Simplified SSL Management**: Easily issue, renew, revoke, and install SSL certificates for your domains.
- **Wildcard Certificate Support**: Issue wildcard SSL certificates with manual DNS verification or Cloudflare DNS integration.
- **Manual DNS Mode Support**: Enhanced support for manual DNS challenges, including verification of multiple TXT records for wildcard certificates.
- **Informative Output**: Provides detailed information about issued SSL certificates, such as validity period, issuer, and subject alternative names.
- **User-Friendly Interface**: Simple command-line interface with clear prompts and error handling.
- **Optimized for Production**: Version 1.2 removes debug output for cleaner logs while maintaining robust error handling and manual DNS verification.

## Menu Options

Here are the options available in ACME SSL Manager and their descriptions:

1. **Update and Install Acme**:
   Updates and upgrades the server, installs `curl` and `socat`, installs the `acme.sh` script, sets Let's Encrypt as the default provider, and registers an account with your email.

2. **Decode SSL Certificate**:
   Displays detailed information about an SSL certificate, including validity period, issuer, subject alternative names, and serial number.

3. **Issue New SSL Certificate**:
   Issues SSL certificate(s) for specified domains using Let's Encrypt in standalone mode (requires domains to point to the server).

4. **Revoke SSL Certificate**:
   Revokes and removes SSL certificate(s) for specified domains from the server.

5. **Renew SSL Certificate**:
   Renews SSL certificate(s) for specified domains using the `acme.sh` script.

6. **Issue Wildcard SSL Certificate for Each Domain Separately**:
   Issues wildcard SSL certificate(s) for each specified domain using Cloudflare DNS integration.

7. **Issue Combined Wildcard SSL Certificate for Multiple Domains**:
   Issues a combined wildcard SSL certificate for multiple domains using Cloudflare DNS integration.

8. **Issue SSL Certificate with Auto Challenge (Supports Wildcard, No Cloudflare)**:
   Issues SSL certificates with automatic challenge handling, supporting both standalone mode (for non-wildcard) and manual DNS mode (for wildcard certificates).

9. **Exit**:
   Exits the program.

## Requirements
- **Python 3.x**
- **curl** and **socat** (installed automatically via option 1)
- **acme.sh** (installed automatically via option 1)
- **OpenSSL** (for decoding certificate information)
- **dig** (for verifying DNS TXT records in manual DNS mode)

## Installation
Clone the repository and run the script `ACME_SSL_Manager_1.2.py`:

```bash
git clone https://github.com/090ebier/ACME_SSL_Manager.git
cd ACME_SSL_Manager
python3 ACME_SSL_Manager_1.2.py
```

## Preview

![Alt text](https://github.com/090ebier/ACME_SSL_Manager/blob/main/Screenshot.png)
