import tkinter as tk
from tkinter import messagebox, filedialog
import os
import socket
import ssl
import requests
from bs4 import BeautifulSoup
import dns.resolver


class WebAppPenTestTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Application Penetration Testing Tool")
        self.root.geometry("600x400")

        self.project_name = None
        self.project_dir = "projects"

        # Main menu
        self.main_menu()

    def main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        btn_new_project = tk.Button(self.root, text="New Project", command=self.new_project)
        btn_new_project.pack(pady=20)

        btn_existing_project = tk.Button(self.root, text="Existing Project", command=self.load_existing_project)
        btn_existing_project.pack(pady=20)

    def new_project(self):
        self.clear_screen()

        tk.Label(self.root, text="Enter Project Name:").pack(pady=10)
        self.project_name_entry = tk.Entry(self.root)
        self.project_name_entry.pack(pady=5)

        tk.Button(self.root, text="Enter", command=self.setup_project).pack(pady=10)

    def setup_project(self):
        self.project_name = self.project_name_entry.get()
        if not self.project_name:
            messagebox.showerror("Error", "Project name cannot be empty")
            return

        project_path = os.path.join(self.project_dir, self.project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path)

        self.scanning_options()

    def scanning_options(self):
        self.clear_screen()

        tk.Label(self.root, text="Enter Domain Name:").pack(pady=10)
        self.domain_entry = tk.Entry(self.root)
        self.domain_entry.pack(pady=5)

        self.scan_options = {
            "IP Lookup": self.ip_lookup,
            "SSL Inspection": self.ssl_inspection,
            "Subdomain Enumeration": self.subdomain_enumeration,
            "Web Crawling": self.web_crawling,
            "Wayback Machine": self.wayback_machine,
            "Social Media Links": self.social_media_links,
            "WHOIS lookup": self.whois_lookup,
            "DNS Enumeration": self.dns_enumeration,
            "Port Scanning": self.port_scanning,
            "Technology Analysis": self.technology_analysis,
            "DMARC Record": self.dmarc_record,
            "Admin Panel": self.admin_panel
        }

        self.selected_options = {}

        for option in self.scan_options:
            var = tk.BooleanVar()
            cb = tk.Checkbutton(self.root, text=option, variable=var)
            cb.pack(anchor='w')
            self.selected_options[option] = var

        tk.Button(self.root, text="Start Scan", command=self.start_scan).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.main_menu).pack(side='left', padx=10, pady=10)
        tk.Button(self.root, text="Save", command=self.save_results).pack(side='right', padx=10, pady=10)

    def start_scan(self):
        domain = self.domain_entry.get()
        if not domain:
            messagebox.showerror("Error", "Domain name cannot be empty")
            return

        self.clear_screen()

        self.results_text = tk.Text(self.root, wrap='word')
        self.results_text.pack(expand=1, fill='both')

        for option, var in self.selected_options.items():
            if var.get():
                scan_function = self.scan_options[option]
                result = scan_function(domain)
                self.results_text.insert(tk.END, f"{option} Results:\n{result}\n\n")

        tk.Button(self.root, text="Back", command=self.scanning_options).pack(side='left', padx=10, pady=10)
        tk.Button(self.root, text="Save", command=self.save_results).pack(side='right', padx=10, pady=10)

    def save_results(self):
        if not self.project_name:
            messagebox.showerror("Error", "No project is loaded")
            return

        project_path = os.path.join(self.project_dir, self.project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path)

        results_file = os.path.join(project_path, "results.txt")
        with open(results_file, "w") as f:
            f.write(self.results_text.get("1.0", tk.END))

        messagebox.showinfo("Info", "Results saved successfully")

    def load_existing_project(self):
        project_path = filedialog.askdirectory(initialdir=self.project_dir)
        if project_path:
            self.project_name = os.path.basename(project_path)
            results_file = os.path.join(project_path, "results.txt")
            if os.path.exists(results_file):
                self.clear_screen()
                with open(results_file, "r") as f:
                    results = f.read()
                self.results_text = tk.Text(self.root, wrap='word')
                self.results_text.pack(expand=1, fill='both')
                self.results_text.insert(tk.END, results)
                tk.Button(self.root, text="Back", command=self.main_menu).pack(side='left', padx=10, pady=10)
                tk.Button(self.root, text="Save", command=self.save_results).pack(side='right', padx=10, pady=10)
            else:
                messagebox.showerror("Error", "No results file found in the selected project")

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def ip_lookup(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)
            return f"IP Address for {domain}: {ip_address}"
        except socket.gaierror:
            return f"Error: Unable to resolve {domain}"

    def ssl_inspection(self, domain):
        context = ssl.create_default_context()

        try:
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_info = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "serialNumber": cert.get('serialNumber'),
                        "version": cert.get('version'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter')
                    }

                    result = "SSL Certificate Details:\n"
                    for key, value in cert_info.items():
                        result += f"{key}: {value}\n"
                    return result
        except Exception as e:
            return f"Error: Unable to inspect SSL certificate for {domain}. {e}"

    def subdomain_enumeration(self, domain):
        subdomains = ["www", "mail", "ftp", "blog"]
        results = []
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                ip_address = socket.gethostbyname(full_domain)
                results.append(f"{full_domain}: {ip_address}")
            except socket.gaierror:
                results.append(f"{full_domain}: Not Found")
        return "\n".join(results)

    def web_crawling(self, domain):
        try:
            url = f"http://{domain}"
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [a['href'] for a in soup.find_all('a', href=True)]
            result = "Found Links:\n" + "\n".join(links)
            return result
        except Exception as e:
            return f"Error: Unable to crawl {domain}. {e}"

    def wayback_machine(self, domain):
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
            response = requests.get(url)
            if response.status_code == 200:
                snapshots = response.json()
                result = "Wayback Machine Snapshots:\n"
                result += "\n".join([f"Snapshot: {snapshot[1]} on {snapshot[2]}" for snapshot in snapshots[1:]])
                return result
            else:
                return f"Error: Unable to retrieve Wayback Machine snapshots for {domain}."
        except Exception as e:
            return f"Error: Unable to retrieve Wayback Machine snapshots for {domain}. {e}"

    def social_media_links(self, domain):
        try:
            url = f"http://{domain}"
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            social_media = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if "facebook.com" in href or "twitter.com" in href or "linkedin.com" in href:
                    social_media.append(href)
            if social_media:
                result = "Social Media Links:\n" + "\n".join(social_media)
            else:
                result = "No Social Media Links found."
            return result
        except Exception as e:
            return f"Error: Unable to retrieve Social Media Links for {domain}. {e}"

    def whois_lookup(self, domain):
        try:
            # Implement your WHOIS lookup logic here
            return f"WHOIS lookup for {domain}"
        except Exception as e:
            return f"Error: Unable to perform WHOIS lookup for {domain}. {e}"

    def dns_enumeration(self, domain):
        try:
            # Implement your DNS enumeration logic here
            return f"DNS Enumeration for {domain}"
        except Exception as e:
            return f"Error: Unable to perform DNS enumeration for {domain}. {e}"

    def port_scanning(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                3389: "RDP"
            }
            open_ports = []
            for port, service in common_ports.items():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        open_ports.append(f"Port {port} ({service}) is open")

            if open_ports:
                return "\n".join(open_ports)
            else:
                return "No common ports are open"
        except socket.gaierror:
            return f"Error: Unable to resolve {domain}"
        except Exception as e:
            return f"Error: Unable to perform port scanning for {domain}. {e}"

    def technology_analysis(self, domain):
        try:
            url = f"http://{domain}"
            response = requests.get(url)
            headers = response.headers
            server = headers.get('Server', 'Unknown')
            x_powered_by = headers.get('X-Powered-By', 'Unknown')
            technologies = f"Server: {server}\nX-Powered-By: {x_powered_by}\n"

            soup = BeautifulSoup(response.text, 'html.parser')
            meta_generator = soup.find('meta', {'name': 'generator'})
            if meta_generator:
                technologies += f"Generator: {meta_generator['content']}\n"

            return technologies if technologies.strip() else "No technology information found."
        except Exception as e:
            return f"Error: Unable to perform technology analysis for {domain}. {e}"

    def dmarc_record(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            dmarc_record = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            result = "DMARC Record:\n"
            for txt_record in dmarc_record:
                result += txt_record.to_text() + "\n"
            return result
        except dns.resolver.NoAnswer:
            return f"No DMARC record found for {domain}."
        except dns.resolver.NXDOMAIN:
            return f"Domain {domain} does not exist."
        except Exception as e:
            return f"Error: Unable to retrieve DMARC record for {domain}. {e}"

    def admin_panel(self, domain):
        common_admin_paths = [
            "admin", "admin/login", "admin/index", "admin/admin", "admin_area/admin", "admin1", "admin2", "admin3",
            "administrator", "administrator/login", "administrator/index", "cpanel", "cpanel/login", "cpanel/index",
            "controlpanel", "controlpanel/login", "controlpanel/index", "login", "login/admin"
        ]
        found_panels = []
        for path in common_admin_paths:
            url = f"http://{domain}/{path}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    found_panels.append(url)
            except requests.RequestException:
                continue

        if found_panels:
            return "Found Admin Panels:\n" + "\n".join(found_panels)
        else:
            return "No Admin Panels found"

if __name__ == "__main__":
    root = tk.Tk()
    app = WebAppPenTestTool(root)
    root.mainloop()
