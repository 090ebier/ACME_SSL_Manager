import subprocess
import os
import signal
import sys
import socket
import time
import re

VERSION = "1.2.2"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

def print_banner():
    banner = f"""
{MAGENTA}╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   .d8b.   .o88b. .88b  d88. d88888b   .d8888. .d8888. db             ║
║  d8' `8b d8P  Y8 88'YbdP`88 88'       88'  YP 88'  YP 88             ║
║  88ooo88 8P      88  88  88 88ooooo   `8bo.   `8bo.   88             ║
║  88~~~88 8b      88  88  88 88~~~~~     `Y8b.   `Y8b. 88             ║
║  88   88 Y8b  d8 88  88  88 88.       db   8D db   8D 88booo.        ║
║  YP   YP  `Y88P' YP  YP  YP Y88888P   `8888Y' `8888Y' Y88888P        ║
║                                                                      ║
║  {CYAN}ACME SSL Manager v{VERSION}{MAGENTA}                                             ║
║  {BLUE}GitHub: https://github.com/090ebier/ACME_SSL_Manager{RESET}{MAGENTA}                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝{RESET}
    """
    print(banner)

def run_command(command, description=None, debug=False):
    if description:
        print(f"{YELLOW}➤ {description}{RESET}")
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_lines = []
    while True:
        output = process.stdout.readline()
        if output:
            print(f"{CYAN}│ {output.strip()}{RESET}")
            output_lines.append(output.strip())
        elif process.poll() is not None:
            break
    rc = process.poll()
    if rc != 0:
        error_output = process.stderr.read()
        print(f"{RED}✗ Error: {command}\n{error_output.strip()}{RESET}")
        if debug:
            print(f"{YELLOW}ℹ Debug info: https://github.com/acmesh-official/acme.sh/wiki/How-to-debug-acme.sh{RESET}")
    return rc == 0, output_lines

def extract_txt_records(output_lines):
    txt_records = []
    txt_pattern = r"TXT value: '([^']+)'"
    txtdomain_pattern = r"Domain: '(_acme-challenge\.[^']+)'"
    keyauth_pattern = r"keyauthorization='([^']+)'"
    
    current_domain = None
    for line in output_lines:
        txt_match = re.search(txt_pattern, line)
        txtdomain_match = re.search(txtdomain_pattern, line)
        keyauth_match = re.search(keyauth_pattern, line)
        
        if txtdomain_match:
            current_domain = txtdomain_match.group(1)
        if txt_match and current_domain:
            txt_records.append({'domain': current_domain, 'value': txt_match.group(1)})
        if keyauth_match and current_domain:
            txt_records.append({'domain': current_domain, 'value': keyauth_match.group(1)})
    
    return txt_records

def update_upgrade_server():
    return run_command("sudo apt update", "Updating server packages...")

def install_packages():
    return run_command("sudo apt install curl socat -y", "Installing dependencies...")

def install_acme_script():
    return run_command("curl https://get.acme.sh | sh", "Installing ACME script...")

def set_default_ca():
    return run_command("~/.acme.sh/acme.sh --set-default-ca --server letsencrypt", "Setting Let’s Encrypt as default CA...")

def register_account(email):
    return run_command(f"~/.acme.sh/acme.sh --register-account -m {email}", f"Registering with email {email}...")

def issue_certificate(domains):
    domain_args = " ".join([f"-d {domain}" for domain in domains])
    return run_command(f"~/.acme.sh/acme.sh --issue --force {domain_args} --standalone", f"Issuing SSL for {', '.join(domains)}...")

def create_directory(domain):
    return run_command(f"mkdir -p /root/full-cert/{domain}", f"Creating directory for {domain}...")

def install_certificate(domain):
    return run_command(f"~/.acme.sh/acme.sh --installcert -d {domain} --key-file /root/full-cert/{domain}/private.key --fullchain-file /root/full-cert/{domain}/cert.crt", f"Installing certificate for {domain}...")

def revoke_certificate(domains):
    domain_args = " ".join([f"-d {domain}" for domain in domains])
    success, _ = run_command(f"~/.acme.sh/acme.sh --revoke {domain_args}", f"Revoking certificates for {', '.join(domains)}...")
    if not success:
        return False
    success, _ = run_command(f"~/.acme.sh/acme.sh --remove {domain_args}", f"Removing certificates for {', '.join(domains)}...")
    if not success:
        return False
    for domain in domains:
        remove_directory(f"/root/full-cert/{domain}")
    return True

def remove_directory(directory):
    if os.path.exists(directory):
        run_command(f"rm -rf {directory}", f"Removing directory {directory}...")

def renew_certificate(domains):
    success = True
    for domain in domains:
        domain_args = f"-d {domain}"
        success, _ = run_command(f"~/.acme.sh/acme.sh --renew --force {domain_args}", f"Renewing certificate for {domain}...")
        if not success or not install_certificate(domain):
            success = False
    return success

def issue_wildcard_certificate(domains, email, api_key):
    os.environ["CF_Email"] = email
    os.environ["CF_Key"] = api_key
    success = True
    for domain in domains:
        command = f"~/.acme.sh/acme.sh --issue --force -d {domain} -d '*.{domain}' --dns dns_cf"
        success, _ = run_command(command, f"Issuing wildcard certificate for {domain}...")
        if not success or not create_directory(domain)[0] or not install_certificate(domain):
            success = False
    return success

def install_combined_certificate(domain):
    wildcard_dir = f"/root/full-cert/{domain}"
    if create_directory(domain):
        return run_command(f"~/.acme.sh/acme.sh --installcert -d {domain} --key-file {wildcard_dir}/private.key --fullchain-file {wildcard_dir}/cert.crt", f"Installing wildcard certificate for {domain}...")
    return False

def signal_handler(sig, frame):
    print(f"{RED}✗ Interrupted. Exiting...{RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def list_domains():
    base_dir = "/root/full-cert"
    if os.path.exists(base_dir):
        return [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    return []

def select_domains(domains):
    print(f"{BLUE}Available domains:{RESET}")
    for idx, domain in enumerate(domains):
        print(f"{CYAN}{idx + 1}. {domain}{RESET}")
    choices = input(f"{YELLOW}➤ Select domains (comma-separated numbers): {RESET}")
    selected_indices = [int(x.strip()) - 1 for x in choices.split(',')]
    return [domains[i] for i in selected_indices]

def decode_certificate_info(cert_file):
    commands = {
        "Subject Alternative Names": f"openssl x509 -in {cert_file} -noout -ext subjectAltName",
        "Valid From": f"openssl x509 -in {cert_file} -noout -startdate | sed 's/notBefore=//'",
        "Valid To": f"openssl x509 -in {cert_file} -noout -enddate | sed 's/notAfter=//'",
        "Issuer": f"openssl x509 -in {cert_file} -noout -issuer | sed 's/issuer=//'",
        "Serial Number": f"openssl x509 -in {cert_file} -noout -serial | sed 's/serial=//'"
    }
    cert_info = {}
    for key, cmd in commands.items():
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        cert_info[key] = output.strip() if process.returncode == 0 else f"Error: {error.strip()}"
    return cert_info

def display_certificate_info(domain):
    cert_file = f"/root/full-cert/{domain}/cert.crt"
    if os.path.exists(cert_file):
        cert_info = decode_certificate_info(cert_file)
        print(f"{GREEN}✓ Certificate info for {domain}:{RESET}")
        for key, value in cert_info.items():
            print(f"{CYAN}  {key}: {value}{RESET}")
    else:
        print(f"{RED}✗ No certificate found for {domain}{RESET}")

def is_domain_pointed_to_server(domain):
    try:
        domain_ip = socket.gethostbyname(domain)
        server_ip = subprocess.check_output(["curl", "-s", "ifconfig.me"]).decode("utf-8").strip()
        return domain_ip == server_ip
    except Exception as e:
        print(f"{RED}✗ Error checking domain {domain}: {e}{RESET}")
        return False

def check_txt_record(txt_domain, expected_value):
    try:
        command = f"dig +short TXT {txt_domain}"
        result = subprocess.check_output(command, shell=True, text=True).strip()
        return expected_value in result
    except Exception as e:
        print(f"{RED}✗ Error checking TXT record for {txt_domain}: {e}{RESET}")
        return False

def issue_with_renew(domain_args, domains, description):
    initial_command = f"~/.acme.sh/acme.sh --issue --force {domain_args} --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please"
    success, output_lines = run_command(initial_command, description, debug=True)
    if not success:
        txt_records = extract_txt_records(output_lines)
        if not txt_records:
            print(f"{RED}✗ No TXT records extracted. Check output and add records manually.{RESET}")
            print(f"{YELLOW}ℹ Possible TXT records: Domain: _acme-challenge.<yourdomain>, look for 'TXT value' or 'keyauthorization'.{RESET}")
            return False

        print(f"{YELLOW}➤ Add these TXT records to your DNS:{RESET}")
        for record in txt_records:
            print(f"{CYAN}  Domain: {record['domain']}{RESET}")
            print(f"{CYAN}  TXT value: {record['value']}{RESET}")
        print(f"{YELLOW}ℹ Note: Wildcard certificates may require multiple TXT records for _acme-challenge.<yourdomain>.{RESET}")
        print(f"{YELLOW}Waiting for DNS propagation...{RESET}")

        max_attempts = 5
        attempt = 1
        while attempt <= max_attempts:
            input(f"{BLUE}Attempt {attempt}/{max_attempts}: Press Enter after adding TXT records...{RESET}")
            all_verified = True
            for record in txt_records:
                if check_txt_record(record['domain'], record['value']):
                    print(f"{GREEN}✓ TXT record for {record['domain']} found!{RESET}")
                else:
                    print(f"{RED}✗ TXT record for {record['domain']} not found yet.{RESET}")
                    all_verified = False
            if all_verified:
                renew_command = f"~/.acme.sh/acme.sh --renew {domain_args} --force --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please"
                success, _ = run_command(renew_command, "Completing issuance after TXT verification...", debug=True)
                if success:
                    return True
                print(f"{RED}✗ Failed issuance. Verify TXT records and try: {renew_command}{RESET}")
                return False
            if attempt < max_attempts:
                print(f"{YELLOW}Waiting 30s before retry {attempt + 1}/{max_attempts}...{RESET}")
                time.sleep(30)
            attempt += 1
        print(f"{RED}✗ Max attempts reached. Verify TXT records and retry.{RESET}")
        return False
    return True

def main():
    while True:
        print_banner()
        print(f"{BLUE}╭─ Options ──────────────────────────────╮{RESET}")
        print(f"{BLUE}│ 1. Update and install ACME            │{RESET}")
        print(f"{BLUE}│ 2. Decode SSL certificate             │{RESET}")
        print(f"{BLUE}│ 3. Issue new SSL certificate          │{RESET}")
        print(f"{BLUE}│ 4. Revoke SSL certificate             │{RESET}")
        print(f"{BLUE}│ 5. Renew SSL certificate              │{RESET}")
        print(f"{BLUE}│ 6. Issue wildcard SSL (per domain)    │{RESET}")
        print(f"{BLUE}│ 7. Issue combined wildcard SSL        │{RESET}")
        print(f"{BLUE}│ 8. Issue SSL with auto challenge      │{RESET}")
        print(f"{BLUE}│ 9. Exit                               │{RESET}")
        print(f"{BLUE}╰───────────────────────────────────────╯{RESET}")
        choice = input(f"{YELLOW}➤ Enter choice (1-9): {RESET}")

        if choice == "1":
            if not update_upgrade_server()[0]:
                print(f"{RED}✗ Failed to update server.{RESET}")
                return
            if not install_packages()[0]:
                print(f"{RED}✗ Failed to install dependencies.{RESET}")
                return
            if not install_acme_script()[0]:
                print(f"{RED}✗ Failed to install ACME script.{RESET}")
                return
            if not set_default_ca()[0]:
                print(f"{RED}✗ Failed to set Let’s Encrypt.{RESET}")
                return
            email = input(f"{YELLOW}➤ Enter email address: {RESET}")
            if not register_account(email)[0]:
                print(f"{RED}✗ Failed to register account.{RESET}")
                return
            print(f"{GREEN}✓ Update and installation completed.{RESET}")

        elif choice == "2":
            available_domains = list_domains()
            if not available_domains:
                print(f"{RED}✗ No domains available.{RESET}")
                continue
            domains = select_domains(available_domains)
            for domain in domains:
                display_certificate_info(domain)
            print(f"{GREEN}✓ Certificate info displayed.{RESET}")

        elif choice == "3":
            domains_input = input(f"{YELLOW}➤ Enter domains (comma-separated): {RESET}")
            domains = [domain.strip() for domain in domains_input.split(',')]
            if domains:
                primary_domain = domains[0]
                if not issue_certificate(domains)[0]:
                    print(f"{RED}✗ Failed to issue certificate.{RESET}")
                    return
                if not create_directory(primary_domain)[0]:
                    print(f"{RED}✗ Failed to create directory for {primary_domain}.{RESET}")
                    return
                if not install_certificate(primary_domain):
                    print(f"{RED}✗ Failed to install certificate for {primary_domain}.{RESET}")
                print(f"{GREEN}✓ Certificate issued and installed.{RESET}")

        elif choice == "4":
            available_domains = list_domains()
            if not available_domains:
                print(f"{RED}✗ No domains available for revocation.{RESET}")
                continue
            domains = select_domains(available_domains)
            if not revoke_certificate(domains):
                print(f"{RED}✗ Failed to revoke certificates.{RESET}")
                return
            print(f"{GREEN}✓ Certificates revoked and removed.{RESET}")

        elif choice == "5":
            available_domains = list_domains()
            if not available_domains:
                print(f"{RED}✗ No domains available for renewal.{RESET}")
                continue
            domains = select_domains(available_domains)
            if not renew_certificate(domains):
                print(f"{RED}✗ Failed to renew certificates.{RESET}")
                return
            print(f"{GREEN}✓ Certificates renewed and installed.{RESET}")

        elif choice == "6":
            domains_input = input(f"{YELLOW}➤ Enter domains (comma-separated): {RESET}")
            domains = [domain.strip() for domain in domains_input.split(',')]
            email = input(f"{YELLOW}➤ Enter Cloudflare email: {RESET}")
            api_key = input(f"{YELLOW}➤ Enter Cloudflare API Key: {RESET}")
            if issue_wildcard_certificate(domains, email, api_key):
                print(f"{GREEN}✓ Wildcard certificates issued.{RESET}")
            else:
                print(f"{RED}✗ Failed to issue wildcard certificates.{RESET}")

        elif choice == "7":
            domains_input = input(f"{YELLOW}➤ Enter domains (comma-separated): {RESET}")
            domains = [domain.strip() for domain in domains_input.split(',')]
            email = input(f"{YELLOW}➤ Enter Cloudflare email: {RESET}")
            api_key = input(f"{YELLOW}➤ Enter Cloudflare API Key: {RESET}")
            combined_domain = domains[0]
            domain_args = " ".join([f"-d {domain}" for domain in domains] + [f"-d '*.{domain}'" for domain in domains])
            success, _ = run_command(f"~/.acme.sh/acme.sh --issue --force {domain_args} --dns dns_cf", f"Issuing combined wildcard for {', '.join(domains)}...")
            if success and create_directory(combined_domain)[0]:
                install_combined_certificate(combined_domain)
            print(f"{GREEN}✓ Combined wildcard certificate issued.{RESET}")

        elif choice == "8":
            wildcard_input = input(f"{YELLOW}➤ Wildcard certificate? (y/n): {RESET}").lower()
            is_wildcard = wildcard_input == 'y'
            domains_input = input(f"{YELLOW}➤ Enter domains (comma-separated): {RESET}")
            domains = [domain.strip() for domain in domains_input.split(',')]
            if not domains:
                print(f"{RED}✗ No domains entered.{RESET}")
                continue
            is_combined = True
            if len(domains) > 1:
                combined_input = input(f"{YELLOW}➤ Combined certificate? (y/n): {RESET}").lower()
                is_combined = combined_input == 'y'

            success = True
            if not is_wildcard:
                all_pointed = all(is_domain_pointed_to_server(domain) for domain in domains)
                domain_args = " ".join(f"-d {domain}" for domain in domains)
                if all_pointed:
                    command = f"~/.acme.sh/acme.sh --issue --force {domain_args} --standalone"
                    success, _ = run_command(command, f"Issuing certificate for {', '.join(domains)}...", debug=True)
                else:
                    if not issue_with_renew(domain_args, domains, f"Issuing certificate for {', '.join(domains)}..."):
                        success = False
                if success:
                    primary_domain = domains[0]
                    if not create_directory(primary_domain)[0] or not install_certificate(primary_domain):
                        success = False
            else:
                if not is_combined:
                    for domain in domains:
                        domain_args = f"-d {domain} -d '*.{domain}'"
                        if not issue_with_renew(domain_args, [domain], f"Issuing wildcard for {domain}..."):
                            success = False
                        if success and (not create_directory(domain)[0] or not install_certificate(domain)):
                            success = False
                else:
                    domain_args = " ".join(f"-d {domain} -d '*.{domain}'" for domain in domains)
                    if not issue_with_renew(domain_args, domains, f"Issuing combined wildcard for {', '.join(domains)}..."):
                        success = False
                    if success:
                        primary_domain = domains[0]
                        if not create_directory(primary_domain)[0] or not install_certificate(primary_domain):
                            success = False
            if success:
                print(f"{GREEN}✓ Certificate issued and installed.{RESET}")
            else:
                print(f"{RED}✗ Failed to issue/install certificate.{RESET}")

        elif choice == "9":
            print(f"{RED}✗ Exiting...{RESET}")
            break

        else:
            print(f"{RED}✗ Invalid choice. Try again.{RESET}")

        input(f"{BLUE}Press Enter to continue...{RESET}")
        run_command("clear", "Clearing screen...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{RED}✗ Interrupted. Exiting...{RESET}")
