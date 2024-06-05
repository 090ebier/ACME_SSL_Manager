import subprocess
import os
import signal
import sys
from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)

def print_banner():
    banner_text = 'ACME SSL Manager v1.0.0'
    banner = pyfiglet.Figlet(font='slant').renderText(banner_text)
    print(Fore.GREEN + Style.BRIGHT + banner + Style.RESET_ALL)


def run_command(command, description=None):
    if description:
        print(Fore.YELLOW + description + Style.RESET_ALL)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while True:
        output = process.stdout.readline()
        if output:
            print(Fore.CYAN + output.strip() + Style.RESET_ALL)
        elif process.poll() is not None:
            break
    rc = process.poll()
    if rc != 0:
        error_output = process.stderr.read()
        print(Fore.RED + f"Error executing command: {command}\n{error_output.strip()}" + Style.RESET_ALL)
    return rc == 0

def update_upgrade_server():
    return run_command("apt update && apt upgrade -y", "Updating and upgrading the server...")

def install_packages():
    return run_command("apt install curl socat -y", "Installing curl and socat...")

def install_acme_script():
    return run_command("curl https://get.acme.sh | sh", "Installing Acme Script...")

def set_default_ca():
    return run_command("~/.acme.sh/acme.sh --set-default-ca --server letsencrypt", "Setting the default provider to Let’s Encrypt...")

def register_account(email):
    return run_command(f"~/.acme.sh/acme.sh --register-account -m {email}", f"Registering account with email {email}...")

def issue_certificate(domains):
    domain_args = " ".join([f"-d {domain}" for domain in domains])
    return run_command(f"~/.acme.sh/acme.sh --issue --force {domain_args} --standalone", f"Issuing SSL certificate for domains: {', '.join(domains)} with force option...")

def create_directory(domain):
    return run_command(f"mkdir -p /root/full-cert/{domain}", f"Creating directory /root/full-cert/{domain}...")

def install_certificate(domain):
    return run_command(f"~/.acme.sh/acme.sh --installcert -d {domain} --key-file /root/full-cert/{domain}/private.key --fullchain-file /root/full-cert/{domain}/cert.crt", f"Installing the certificate for {domain}...")

def revoke_certificate(domains):
    domain_args = " ".join([f"-d {domain}" for domain in domains])
    if not run_command(f"~/.acme.sh/acme.sh --revoke {domain_args}", f"Revoking SSL certificates for domains: {', '.join(domains)}..."):
        return False
    if not run_command(f"~/.acme.sh/acme.sh --remove {domain_args}", f"Removing SSL certificates for domains: {', '.join(domains)}..."):
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
        if not run_command(f"~/.acme.sh/acme.sh --renew --force {domain_args}", f"Renewing SSL certificate for domain: {domain}..."):
            success = False
        if not install_certificate(domain):
            success = False
    return success

def issue_wildcard_certificate(domains, email, api_key):
    os.environ["CF_Email"] = email
    os.environ["CF_Key"] = api_key
    success = True
    for domain in domains:
        command = f"~/.acme.sh/acme.sh --issue --force -d {domain} -d '*.{domain}' --dns dns_cf"
        if not run_command(command, f"Issuing wildcard SSL certificate for domain: {domain}..."):
            success = False
        wildcard_dir = f"/root/full-cert/{domain}"
        if not create_directory(domain):
            success = False
        if not install_certificate(domain):
            success = False
    return success

def install_combined_certificate(domain):
    wildcard_dir = f"/root/full-cert/{domain}"
    if create_directory(domain):
        return run_command(f"~/.acme.sh/acme.sh --installcert -d {domain} --key-file {wildcard_dir}/private.key --fullchain-file {wildcard_dir}/cert.crt", f"Installing wildcard certificate for {domain}...")
    return False

def signal_handler(sig, frame):
    print(Fore.RED + "\nExiting due to user interrupt..." + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def list_domains():
    base_dir = "/root/full-cert"
    if os.path.exists(base_dir):
        return [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    return []

def select_domains(domains):
    print(Fore.BLUE + "Available domains:")
    for idx, domain in enumerate(domains):
        print(f"{idx + 1}. {domain}")
    choices = input(Fore.YELLOW + "Enter the numbers of the domains you want to select, separated by commas: " + Style.RESET_ALL)
    selected_indices = [int(x.strip()) - 1 for x in choices.split(',')]
    return [domains[i] for i in selected_indices]

def decode_certificate_info(cert_file):
   
    commands = {
        "Subject Alternative Names ": f"openssl x509 -in {cert_file} -noout -ext subjectAltName",
        "Valid From ": f"openssl x509 -in {cert_file} -noout -startdate | sed 's/notBefore=//'",
        "Valid To ": f"openssl x509 -in {cert_file} -noout -enddate | sed 's/notAfter=//'",
        "Issuer ": f"openssl x509 -in {cert_file} -noout -issuer | sed 's/issuer=//'",
        "Serial Number ": f"openssl x509 -in {cert_file} -noout -serial | sed 's/serial=//'"
    }
    cert_info = {}
    for key, cmd in commands.items():
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        if process.returncode == 0:
            cert_info[key] = output.strip()
        else:
            cert_info[key] = f"Error: {error.strip()}"
    return cert_info

def display_certificate_info(domain):
    cert_file = f"/root/full-cert/{domain}/cert.crt"
    if os.path.exists(cert_file):
        cert_info = decode_certificate_info(cert_file)
        print(Fore.GREEN + f"Certificate information for {domain}:" + Style.RESET_ALL)
        for key, value in cert_info.items():
            print(f"{key}: {value}")
    else:
        print(Fore.RED + f"No certificate found for {domain}" + Style.RESET_ALL)

def main():
    while True:
        print_banner()
        print(Fore.BLUE + "Choose an option:")
        print("1. Update and install Acme")
        print("2. Decode SSL certificate")
        print("3. Issue new SSL certificate")
        print("4. Revoke SSL certificate")
        print("5. Renew SSL certificate")
        print("6. Issue wildcard SSL certificate for each domain separately")
        print("7. Issue combined wildcard SSL certificate for multiple domains")
        print("8. Exit")
        choice = input("Enter your choice (1/2/3/4/5/6/7/8): ")

        if choice == "1":
            if not update_upgrade_server():
                print(Fore.RED + "Failed to update and upgrade the server. Exiting...")
                return
            if not install_packages():
                print(Fore.RED + "Failed to install curl and socat. Exiting...")
                return
            if not install_acme_script():
                print(Fore.RED + "Failed to install Acme Script. Exiting...")
                return
            if not set_default_ca():
                print(Fore.RED + "Failed to set the default provider to Let’s Encrypt. Exiting...")
                return
            email = input(Fore.YELLOW + "Please enter your email address: ")
            if not register_account(email):
                print(Fore.RED + "Failed to register account. Exiting...")
                return
            print(Fore.GREEN + "Update and installation completed successfully.")

        elif choice == "2":
            available_domains = list_domains()
            if not available_domains:
                print(Fore.RED + "No domains available for decoding.")
                continue
            domains = select_domains(available_domains)
            for domain in domains:
                display_certificate_info(domain)
            print(Fore.GREEN + "SSL certificate information displayed successfully.")

        elif choice == "3":
            domains_input = input(Fore.YELLOW + "Please enter your domain names, separated by commas (e.g., host1.mydomain.com,host2.mydomain.com): ")
            domains = [domain.strip() for domain in domains_input.split(',')]
            if domains:
                primary_domain = domains[0]
                if not issue_certificate(domains):
                    print(Fore.RED + "Failed to issue SSL certificate. Exiting...")
                    return
                if not create_directory(primary_domain):
                    print(Fore.RED + f"Failed to create directory for {primary_domain}. Exiting...")
                    return
                if not install_certificate(primary_domain):
                    print(Fore.RED + f"Failed to install certificate for {primary_domain}. Exiting...")
                print(Fore.GREEN + "SSL certificate issued and installed successfully.")

        elif choice == "4":
            available_domains = list_domains()
            if not available_domains:
                print(Fore.RED + "No domains available for revocation.")
                continue
            domains = select_domains(available_domains)
            if not revoke_certificate(domains):
                print(Fore.RED + "Failed to revoke and remove SSL certificates. Exiting...")
                return
            print(Fore.GREEN + "SSL certificates revoked and removed successfully.")

        elif choice == "5":
            available_domains = list_domains()
            if not available_domains:
                print(Fore.RED + "No domains available for renewal.")
                continue
            domains = select_domains(available_domains)
            if not renew_certificate(domains):
                print(Fore.RED + "Failed to renew SSL certificates. Exiting...")
                return
            print(Fore.GREEN + "SSL certificates renewed and installed successfully.")

        elif choice == "6":
            domains_input = input(Fore.YELLOW + "Please enter your domain names, separated by commas (e.g., mydomain.com,myotherdomain.com): ")
            domains = [domain.strip() for domain in domains_input.split(',')]
            email = input("Please enter your Cloudflare email: ")
            api_key = input("Please enter your Cloudflare Global API Key: ")
            if issue_wildcard_certificate(domains, email, api_key):
                print(Fore.GREEN + "Wildcard SSL certificates issued and installed successfully.")
            else:
                print(Fore.RED + "Failed to issue some wildcard SSL certificates. Exiting...")

        elif choice == "7":
            domains_input = input(Fore.YELLOW + "Please enter your domain names, separated by commas (e.g., mydomain.com,myotherdomain.com): ")
            domains = [domain.strip() for domain in domains_input.split(',')]
            email = input("Please enter your Cloudflare email: ")
            api_key = input("Please enter your Cloudflare Global API Key: ")
            combined_domain = domains[0]
            domain_args = " ".join([f"-d {domain}" for domain in domains] + [f"-d '*.{domain}'" for domain in domains])
            command = f"~/.acme.sh/acme.sh --issue --force {domain_args} --dns dns_cf"
            if run_command(command, f"Issuing combined wildcard SSL certificate for domains: {', '.join(domains)}..."):
                wildcard_dir = f"/root/full-cert/{combined_domain}"
                if create_directory(combined_domain):
                    install_combined_certificate(combined_domain)
            print(Fore.GREEN + "Combined wildcard SSL certificate issued and installed successfully.")

        elif choice == "8":
            print(Fore.RED + "Exiting...")
            break

        else:
            print(Fore.RED + "Invalid choice. Please try again.")

        input(Fore.BLUE + "Press Enter to continue...")
        run_command("clear", "Clearing screen...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nExiting due to user interrupt..." + Style.RESET_ALL)
