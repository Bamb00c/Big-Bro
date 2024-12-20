import ctypes
import sys
import os
import psutil
import time
import tkinter as tk
from tkinter import ttk, messagebox
from plyer import notification
from threading import Thread
import requests
from ipaddress import ip_network, ip_address as ip_addr
import socket
import time
from pystray import Icon, MenuItem, Menu
from PIL import Image, ImageDraw
import winsound
from win10toast import ToastNotifier
# Cloudflare IP ünvanlarının siyahısı
CLOUDFLARE_IPS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
]
notifier = ToastNotifier()

def send_notification(title, message):
    notifier.show_toast(title, message, duration=10, icon_path=r"C:\Users\Student\Desktop\Alert_elvin\eye.ico")
# Fayl adları
BIG_BRO_DIR = r"C:\Big Bro"
VIRUSTOTAL_API_KEY_FILE = os.path.join(BIG_BRO_DIR, "virustotal_api_key.txt")
ABUSEIPDB_API_KEY_FILE = os.path.join(BIG_BRO_DIR, "abuseipdb_api_key.txt")
if not os.path.exists(BIG_BRO_DIR):
    os.makedirs(BIG_BRO_DIR)
# Fayldan API açarlarını oxumaq və saxlamaq
def load_api_key(file_path):
    """ API açarını fayldan oxuyur """
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return file.read().strip()
    return ""

def save_api_key(api_key, file_path):
    """ API açarını faylda saxlayır """
    with open(file_path, "w") as file:
        file.write(api_key)

# Global API açarlarını yükləyirik
VIRUSTOTAL_API_KEY = load_api_key(VIRUSTOTAL_API_KEY_FILE)
ABUSEIPDB_API_KEY = load_api_key(ABUSEIPDB_API_KEY_FILE)

# Admin hüquqları ilə işləmə funksiyası
def run_as_admin():
    """ Relaunch the script as admin if not already running as admin """
    if not is_admin():
        script = sys.argv[0]
        params = " ".join(sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)

def is_admin():
    """ Check if the script is running as admin """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not is_admin():
    run_as_admin()

# Əvvəlki əlaqələri saxlamaq üçün set yaradılır
previous_connections = set()
last_connection = None
process_info = {}  # Proses məlumatlarını saxlamaq üçün əlavə bir lüğət
all_rows = []  # Backup of all rows in the table

# İstisna edilmiş IP-lərin siyahısı
EXCLUDED_IPS = {"127.0.0.1", "8.8.8.8", "8.8.4.4", "4.4.4.4"}
def create_tray_icon(root, show_callback, exit_callback):
    image = Image.open(r"C:\Users\Student\Desktop\Alert_elvin\eye.ico")

    def on_show(icon, item):
        show_callback(icon)

    def on_exit(icon, item):
        exit_callback(icon)

    menu = Menu(
        MenuItem("Show", on_show),
        MenuItem("Exit", on_exit)
    )

    tray_icon = Icon("BigBro", image, "Big Bro Monitor", menu)
    return tray_icon

# Network Card Selector GUI
class NetworkCardSelector:
    def __init__(self, root):
        self.root = root
        self.root.title("Big Bro")
        self.root.iconbitmap(r"C:\Users\Student\Desktop\Alert_elvin\eye.ico")

        # Pəncərə ölçüləri
        window_width = 500
        window_height = 500

        # Ekranın ölçülərini əldə edirik
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Mərkəz koordinatlarını hesablayırıq
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Pəncərəni mərkəzə yerləşdiririk
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.configure(bg="#2e2e2e")

        self.title_label = tk.Label(self.root, text="Select Network Interface", font=("Arial", 16), bg="#2e2e2e", fg="#ffffff")
        self.title_label.pack(pady=20)

        self.adapters = self.get_network_adapters()

        self.adapter_var = tk.StringVar()
        self.adapter_dropdown = ttk.Combobox(self.root, textvariable=self.adapter_var, font=("Arial", 12))
        self.adapter_dropdown["values"] = self.adapters
        self.adapter_dropdown.pack(pady=10)
        self.adapter_dropdown.current(0)

        self.select_button = tk.Button(self.root, text="Start Monitoring", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.start_monitoring)
        self.select_button.pack(pady=20)
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)
        
        self.api_label = tk.Label(self.root, text="Enter VirusTotal API Key:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.api_label.pack(pady=5)

        self.api_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.api_entry.pack(pady=5)
        if VIRUSTOTAL_API_KEY:
            self.api_entry.insert(0, "******-******-******-******-******")

        # Frame for VirusTotal buttons
        api_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        api_button_frame.pack(pady=5)

        self.save_api_button = tk.Button(api_button_frame, text="Save API Key", font=("Arial", 10), command=self.save_api_key, bg="#00661d", fg="#ffffff", relief="flat")
        self.save_api_button.pack(side="left", padx=5)

        self.delete_api_button = tk.Button(api_button_frame, text="Delete API Key", font=("Arial", 10), command=self.delete_api_key, bg="#830000", fg="#ffffff", relief="flat")
        self.delete_api_button.pack(side="left", padx=5)

        # === AbuseIPDB API Key Section ===
        self.abuse_api_label = tk.Label(self.root, text="Enter AbuseIPDB API Key:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.abuse_api_label.pack(pady=5)

        self.abuse_api_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.abuse_api_entry.pack(pady=5)
        if ABUSEIPDB_API_KEY:
            self.abuse_api_entry.insert(0, "******-******-******-******-******")

        # Frame for AbuseIPDB buttons
        abuse_api_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        abuse_api_button_frame.pack(pady=5)

        self.save_abuse_api_button = tk.Button(abuse_api_button_frame, text="Save AbuseAPI Key", font=("Arial", 10), command=self.save_abuse_api_key, bg="#00661d", fg="#ffffff", relief="flat")
        self.save_abuse_api_button.pack(side="left", padx=5)

        self.delete_abuse_api_button = tk.Button(abuse_api_button_frame, text="Delete AbuseAPI Key", font=("Arial", 10), command=self.delete_abuse_api_key, bg="#830000", fg="#ffffff", relief="flat")
        self.delete_abuse_api_button.pack(side="left", padx=5)


    def get_network_adapters(self):
        return list(psutil.net_if_addrs().keys())

    def start_monitoring(self):
        selected_adapter = self.adapter_var.get()
        if selected_adapter not in self.adapters:
            tk.messagebox.showerror("Error", "Invalid adapter selected!")
            return
        self.root.withdraw()
        

        # Yeni pəncərə yaradılır
        new_window = tk.Toplevel(self.root)
        new_window.title("Monitoring Connections")
        new_window.iconbitmap(r"C:\Users\Student\Desktop\Alert_elvin\eye.ico")

        # Yeni pəncərənin ilkin ölçülərini təyin edirik
        new_window.geometry("1024x800")
        new_window.configure(bg="#2e2e2e")

        # Pəncərəni yüklədikdən sonra ölçüləri əldə edirik
        new_window.update_idletasks()
        window_width = new_window.winfo_width()
        window_height = new_window.winfo_height()

        # Ekranın ölçülərini əldə edirik
        screen_width = new_window.winfo_screenwidth()
        screen_height = new_window.winfo_screenheight()

        # Mərkəz koordinatlarını hesablayırıq
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Yeni koordinatları tətbiq edirik
        new_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Yeni pəncərədə tətbiqi işə salırıq
        app = ConnectionMonitorApp(new_window, selected_adapter)
    def minimize_to_tray(self):
        """ Pəncərəni tray ikonuna göndər """
        self.root.withdraw()  # Pəncərəni gizlədin
        tray_icon = create_tray_icon(self.root)  # Tray ikonunu yaradın
        Thread(target=tray_icon.run, daemon=True).start()
    def save_api_key(self):
        global VIRUSTOTAL_API_KEY
        VIRUSTOTAL_API_KEY = self.api_entry.get()
        save_api_key(VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_FILE)
        self.api_entry.delete(0, tk.END)
        self.api_entry.insert(0, "******-******-******-******-******")
        messagebox.showinfo("API Key Saved", "VirusTotal API key has been saved.")

    def delete_api_key(self):
        """ VirusTotal API açarını silmək """
        global VIRUSTOTAL_API_KEY
        VIRUSTOTAL_API_KEY = ""
        self.api_entry.delete(0, tk.END)
        os.remove(VIRUSTOTAL_API_KEY_FILE)  # API açarını fayldan silmək
        messagebox.showinfo("API Key Deleted", "VirusTotal API key has been deleted.")

    def save_abuse_api_key(self):
        global ABUSEIPDB_API_KEY
        ABUSEIPDB_API_KEY = self.abuse_api_entry.get()
        save_api_key(ABUSEIPDB_API_KEY, ABUSEIPDB_API_KEY_FILE)
        self.abuse_api_entry.delete(0, tk.END)
        self.abuse_api_entry.insert(0, "******-******-******-******-******")
        messagebox.showinfo("API Key Saved", "AbuseIPDB API key has been saved.")

    def delete_abuse_api_key(self):
        """ AbuseIPDB API açarını silmək """
        global ABUSEIPDB_API_KEY
        ABUSEIPDB_API_KEY = ""
        self.abuse_api_entry.delete(0, tk.END)
        os.remove(ABUSEIPDB_API_KEY_FILE)  # API açarını fayldan silmək
        messagebox.showinfo("API Key Deleted", "AbuseIPDB API key has been deleted.")

# GUI yaratmaq üçün tkinter istifadə edirik
class ConnectionMonitorApp:
    def __init__(self, root, adapter):
        self.start_time = time.time()
        self.root = root
        self.adapter = adapter
        self.running = True
        self.root.title("Big Bro")
        self.root.iconbitmap(r"C:\Users\Student\Desktop\Alert_elvin\eye.ico")
        self.root.geometry("1200x900")  # Increase window size
        self.root.configure(bg="#2e2e2e")

        # Title
        self.title_label = tk.Label(self.root, text=f"Monitoring: {adapter}", font=("Arial", 18, 'bold'), bg="#2e2e2e", fg="#ffffff")
        self.title_label.pack(pady=20)

        # Search for IP
        self.search_ip_label = tk.Label(self.root, text="Search by IP:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.search_ip_label.pack(pady=5)

        self.search_ip_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.search_ip_entry.pack(pady=5)

        # Frame to hold the buttons for filtering IP
        ip_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        ip_button_frame.pack(pady=5)

        # Filter by IP Button
        self.search_ip_button = tk.Button(ip_button_frame, text="Filter by IP", font=("Arial", 10), command=self.filter_by_ip, bg="#016c87", fg="#ffffff", relief="flat")
        self.search_ip_button.pack(side="left", padx=5)

        # Clear IP Filter Button
        self.clear_ip_button = tk.Button(ip_button_frame, text="Clear IP Filter", font=("Arial", 10), command=self.clear_ip_filter, bg="#016c87", fg="#ffffff", relief="flat")
        self.clear_ip_button.pack(side="left", padx=5)

        # Search for Port
        self.search_port_label = tk.Label(self.root, text="Search by Port:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.search_port_label.pack(pady=5)

        self.search_port_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.search_port_entry.pack(pady=5)

        # Frame to hold the buttons for filtering Port
        port_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        port_button_frame.pack(pady=5)

        # Filter by Port Button
        self.search_port_button = tk.Button(port_button_frame, text="Filter by Port", font=("Arial", 10), command=self.filter_by_port, bg="#016c87", fg="#ffffff", relief="flat")
        self.search_port_button.pack(side="left", padx=5)

        # Clear Port Filter Button
        self.clear_port_button = tk.Button(port_button_frame, text="Clear Port Filter", font=("Arial", 10), command=self.clear_port_filter, bg="#016c87", fg="#ffffff", relief="flat")
        self.clear_port_button.pack(side="left", padx=5)

        # Treeview table to show connection details
        self.tree = ttk.Treeview(
        self.root,
        columns=("IP", "Port", "Protocol", "Process", "Country", "Cloudflare", "VirusTotal", "AbuseIPDB"),
        show="headings",
        height=15)
        
        self.tree.pack(pady=20)
        
                # Checkbox Frame
        self.checkbox_frame = tk.Frame(self.root, bg="#2e2e2e")
        self.checkbox_frame.pack(pady=10)

        # Variables for Checkboxes
        self.all_events_var = tk.BooleanVar(value=False)
        self.suspicious_var = tk.BooleanVar(value=True)

        # All Events Checkbox
        self.all_events_checkbox = tk.Checkbutton(
            self.checkbox_frame, text="All Events", variable=self.all_events_var, bg="#2e2e2e", fg="#ffffff",
            selectcolor="#2e2e2e", activebackground="#2e2e2e", activeforeground="#ffffff", command=self.update_checkboxes
        )
        self.all_events_checkbox.pack(side="left", padx=10)

        # Only Suspicious and Malicious Checkbox
        self.suspicious_checkbox = tk.Checkbutton(
            self.checkbox_frame, text="Only Suspicious and Malicious", variable=self.suspicious_var, bg="#2e2e2e", fg="#ffffff",
            selectcolor="#2e2e2e", activebackground="#2e2e2e", activeforeground="#ffffff", command=self.update_checkboxes
        )
        self.suspicious_checkbox.pack(side="left", padx=10)

        # Adjusting the padding for each column in the table
        self.tree.heading("IP", text="IP Address", anchor="w", command=lambda: self.sort_treeview("IP"))
        self.tree.heading("Port", text="Port", anchor="w", command=lambda: self.sort_treeview("Port"))
        self.tree.heading("Protocol", text="Protocol", anchor="w", command=lambda: self.sort_treeview("Protocol"))
        self.tree.heading("Process", text="Process", anchor="w", command=lambda: self.sort_treeview("Process"))
        self.tree.heading("Country", text="Country", anchor="w", command=lambda: self.sort_treeview("Country"))
        self.tree.heading("Cloudflare", text="Cloudflare", anchor="w", command=lambda: self.sort_treeview("Cloudflare"))
        self.tree.heading("VirusTotal", text="VirusTotal", anchor="w", command=lambda: self.sort_treeview("VirusTotal"))
        self.tree.heading("AbuseIPDB", text="AbuseIPDB", anchor="w", command=lambda: self.sort_treeview("AbuseIPDB"))

        # Setting column widths and padding
        self.tree.column("IP", width=150, anchor="w")
        self.tree.column("Port", width=100, anchor="w")
        self.tree.column("Protocol", width=100, anchor="w")
        self.tree.column("Process", width=150, anchor="w")
        self.tree.column("Country", width=150, anchor="w")
        self.tree.column("Cloudflare", width=100, anchor="w")
        self.tree.column("VirusTotal", width=120, anchor="w")
        self.tree.column("AbuseIPDB", width=120, anchor="w")

        # Adding padding for the cell text
        style = ttk.Style()
        style.configure("Treeview", padding=10)

        # Scrollbar for the Treeview table
        self.scrollbar = tk.Scrollbar(self.root, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.scrollbar.pack(side=tk.TOP, fill=tk.X)

        # Link scrollbar with Treeview
        self.tree.config(yscrollcommand=self.scrollbar.set)

        # Connection Status Label
        self.status_label = tk.Label(self.root, text="Big Bro can see everything...", font=("Arial", 12), bg="#2e2e2e", fg="#f90f00")
        self.status_label.pack(pady=10)

        # Button to Kill Connection
        button_frame = tk.Frame(self.root, bg="#2e2e2e")
        button_frame.pack(pady=15)
        self.kill_button = tk.Button(button_frame, text="Kill Connection", font=("Arial", 12), bg="#830000", fg="#ffffff", command=self.kill_connection, relief="raised")
        self.kill_button.pack(side="left", padx=10)

        # Button to Block IP
        self.block_button = tk.Button(button_frame, text="Block IP", font=("Arial", 12), bg="#830000", fg="#ffffff", command=self.block_ip, relief="raised")
        self.block_button.pack(side="left", padx=10)
        self.back_button = tk.Button(button_frame, text="Back", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.go_back, relief="raised")
        self.back_button.pack(side="left", padx=10)

        # Start monitoring connections in a separate thread
        self.monitor_thread = Thread(target=self.monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Sorting functionality
        self.sorted_column = None
        self.reverse_sort = False

        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.tray_icon = None
        self.tree.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.tree.yview)
    def hide_to_tray(self):
        self.root.withdraw()
        self.tray_icon = create_tray_icon(
        self.root,
        show_callback=self.show_window,
        exit_callback=self.exit_program
        )
        Thread(target=self.tray_icon.run, daemon=True).start()

    def show_window(self, icon):
        """ Show the monitoring window again """
        self.root.deiconify()
        icon.stop()  # Stop the tray icon loop

    def exit_program(self, icon):
        """ Exit the entire application """
        icon.stop()
        self.root.destroy()
        sys.exit()

    # def get_url_from_ip(self, ip_address):
    #     """IP adresinden URL (hostname) bilgisini getirir."""
    #     try:
    #         return socket.gethostbyaddr(ip_address)[0]
    #     except socket.herror:
    #         return "Unknown"   
    def sort_treeview(self, column):
        if self.sorted_column == column:
            self.reverse_sort = not self.reverse_sort
        else:
            self.reverse_sort = False
            self.sorted_column = column

        # Sorting the Treeview based on the selected column
        items = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        items.sort(key=lambda x: x[0], reverse=self.reverse_sort)

        # Re-inserting the sorted items back into the Treeview
        for index, item in enumerate(items):
            self.tree.move(item[1], '', index)

    # Filter and clear functions (you can define your own)
    def filter_by_ip(self):
        # Filtering logic for IP (you can customize this based on your requirements)
        pass

    def clear_ip_filter(self):
        # Clear IP filter logic
        pass

    def filter_by_port(self):
        # Filtering logic for Port
        pass

    def clear_port_filter(self):
        # Clear Port filter logic
        pass

    def kill_connection(self):
        # Logic for killing the connection
        pass

    def block_ip(self):
        # Logic for blocking the IP
        pass
    def go_back(self):
        """ Geri dönmək və monitorinqi dayandırmaq """
        self.running = False
        self.root.destroy()  # Cari pəncərəni bağlayırıq
        main_window.deiconify()
  # Cari pəncərəni bağlayırıq
      
    def monitor_connections(self):
        # Monitoring connections logic (this will run in a separate thread)
        pass

    def check_connections(self):
        global previous_connections, last_connection, process_info, all_rows

        # Bütün əlaqələri yoxlayırıq
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.raddr.ip not in EXCLUDED_IPS:  # Yalnız istisna edilməyən IP-ləri yoxlayırıq
                connection_tuple = (conn.raddr.ip, conn.raddr.port)

                if connection_tuple not in previous_connections:
                    previous_connections.add(connection_tuple)

                    # IP ünvanına əsaslanaraq ölkəni tapırıq
                    country = self.get_country(conn.raddr.ip)
                    cloudflare_status = self.is_cloudflare_ip(conn.raddr.ip)  # Cloudflare yoxlanışı
                    virustotal_status = self.check_virustotal(conn.raddr.ip)  # VirusTotal yoxlanışı
                    abuseipdb_status = self.check_abuseipdb(conn.raddr.ip)  # AbuseIPDB yoxlanışı
                    process_name = psutil.Process(conn.pid).name() if conn.pid else 'Unknown'
                    protocol = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"
                    # url = self.get_url_from_ip(conn.raddr.ip)  # IP'den URL bilgisini alıyoruz

                    # Proses məlumatlarını saxlayırıq
                    process_info[connection_tuple] = (process_name, conn)

                    # Add row to the treeview and backup
                    row_id = self.tree.insert(
                        "", tk.END,
                        values=(conn.raddr.ip,  conn.raddr.port, protocol, process_name, country, cloudflare_status, virustotal_status, abuseipdb_status)
                    )
                    all_rows.append((row_id, (conn.raddr.ip,  conn.raddr.port, protocol, process_name, country, cloudflare_status, virustotal_status, abuseipdb_status)))

                    # Alert göndərmək
                    self.send_alert(conn, virustotal_status, abuseipdb_status, country, cloudflare_status)

    def check_virustotal(self, ip_address):
        """ IP ünvanını Virustotal ilə yoxlamaq """
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            if response.status_code == 200:
                # Checking the number of malicious detections
                malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
                
                if malicious_count >= 3:
                    return "Malicious"  # 3 or more malicious detections
                elif malicious_count >= 1:
                    return "Suspicious"  # 1 or 2 malicious detections
                else:
                    return "Clean"  # No malicious detections
            else:
                return "Error"
        except Exception as e:
            return "Error"

    def check_abuseipdb(self, ip_address):
        """ IP ünvanını AbuseIPDB ilə yoxlamaq """
        url = f'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        try:
            response = requests.get(url, headers=headers, params={'ipAddress': ip_address})
            data = response.json()
            if response.status_code == 200:
                abuse_score = data['data']['abuseConfidenceScore']
                if abuse_score >= 80:
                    return f"High Risk ({abuse_score})"
                elif abuse_score >= 40:
                    return f"Medium Risk ({abuse_score})"
                else:
                    return f"Low Risk ({abuse_score})"
            else:
                return "Error"
        except Exception as e:
            return "Error"

    def is_cloudflare_ip(self, ip_address):
        """ IP ünvanının Cloudflare-ə aid olub olmadığını yoxlamaq """
        for network in CLOUDFLARE_IPS:
            if ip_addr(ip_address) in ip_network(network):
                return "Yes"
        return "No"

    def get_country(self, ip_address):
        """ IP ünvanından ölkə məlumatını almaq """
        try:
            response = requests.get(f'https://geolocation-db.com/json/{ip_address}&position=true').json()
            return response.get("country_name", "Unknown")
        except requests.exceptions.RequestException:
            return "Unknown"

    def monitor_connections(self):
        while self.running:
            try:
                if not self.tree.winfo_exists():  # `Treeview` mövcudluğunu yoxlayırıq
                    break
                self.check_connections()
                time.sleep(2)
            except Exception as e:
                print(f"Monitoring error: {e}")

    def filter_by_ip(self):
        """ IP ünvanına əsasən əlaqələri süzgəcdən keçirmək """
        search_ip = self.search_ip_entry.get()
        if search_ip:
            # Ağacı təmizlə, amma məlumatları silmə
            self.tree.delete(*self.tree.get_children())
            for row_id, values in all_rows:
                ip = values[0]
                if search_ip in ip:
                    self.tree.insert("", tk.END, iid=row_id, values=values)

    def clear_ip_filter(self):
        """ IP filterini təmizləmək və əvvəlki məlumatları qaytarmaq """
        self.search_ip_entry.delete(0, tk.END)
        self.tree.delete(*self.tree.get_children())
        for row_id, values in all_rows:
            self.tree.insert("", tk.END, iid=row_id, values=values)

    def filter_by_port(self):
        """ Port nömrəsinə əsasən əlaqələri süzgəcdən keçirmək """
        search_port = self.search_port_entry.get()
        if search_port:
            # Ağacı təmizlə, amma məlumatları silmə
            self.tree.delete(*self.tree.get_children())
            for row_id, values in all_rows:
                port = str(values[1])  # Port nömrəsi
                if search_port in port:
                    self.tree.insert("", tk.END, iid=row_id, values=values)

    def clear_port_filter(self):
        """ Port filterini təmizləmək və əvvəlki məlumatları qaytarmaq """
        self.search_port_entry.delete(0, tk.END)
        self.tree.delete(*self.tree.get_children())
        for row_id, values in all_rows:
            self.tree.insert("", tk.END, iid=row_id, values=values)


    def update_checkboxes(self):
        """Checkbox durumlarını günceller"""
        if self.all_events_var.get():
            self.suspicious_var.set(False)
        elif self.suspicious_var.get():
            self.all_events_var.set(False)
    
    def send_alert(self, conn, virustotal_status, abuseipdb_status, country, cloudflare_status):
        """Yeni əlaqə haqqında bildiriş göndərmək"""

        ip = conn.raddr.ip
        port = conn.raddr.port

        # Proses adını alırıq
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except psutil.NoSuchProcess:
                process_name = 'Unknown'
        else:
            process_name = 'Unknown'

        # Checkbox durumuna görə filtr
        if self.suspicious_var.get():
            if not ("Malicious" in virustotal_status or 
                    "Suspicious" in virustotal_status or 
                    "Medium Risk" in abuseipdb_status or 
                    "High Risk" in abuseipdb_status):
                return  # Əgər nəticələr riskli deyilsə, bildiriş göndərməyin

        # Emoji əsaslı bildiriş məzmunu
        country_emoji = "🌍" if country != "Unknown" else "❓"
        cloudflare_emoji = "☁️" if cloudflare_status == "Yes" else "🚫"
        virustotal_emoji = "💀" if "Malicious" in virustotal_status else "⚠️" if "Suspicious" in virustotal_status else "✅"
        abuse_emoji = "🔥" if "High Risk" in abuseipdb_status else "⚖️" if "Medium Risk" in abuseipdb_status else "🔒"

        if "Malicious" in virustotal_status or "High Risk" in abuseipdb_status:
            event_type_emoji = "💥 Danger"
            sound_type = "malicious"
        elif "Suspicious" in virustotal_status or "Medium Risk" in abuseipdb_status:
            event_type_emoji = "⚠️ Warning"
            sound_type = "warning"
        else:
            event_type_emoji = "✅ Info"
            sound_type = None

        # Bildiriş mesajını yarat
        alert_message = (
            f"🌐 IP: {ip}:{port} | 💻 Process: {process_name}\n"
            f"🌏 Country: {country} | {cloudflare_emoji} Cloudflare: {cloudflare_status}\n"
            f"{virustotal_emoji} VirusTotal: {virustotal_status}\n"
            f"🔍 AbuseIPDB {abuse_emoji}: {abuseipdb_status}\n"
            "👁️ Big Bro says: Don't trust Microsoft services."
        )

        notification_title = f"Event Type: {event_type_emoji}"

        # Yeni bildiriş funksiyasını çağır
        send_notification(notification_title, alert_message)

        # Riskli vəziyyətlər üçün səs çal
        if sound_type == "malicious":
            winsound.MessageBeep(winsound.MB_ICONHAND)  # Malicious üçün kritik səs
        elif sound_type == "warning":
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)


    

    def kill_connection(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], 'values')
            ip = values[0]
            port = int(values[2])  # Corrected index for Port

            answer = messagebox.askyesno(
                "Confirm Kill", f"Are you sure you want to kill the connection to {ip}:{port}?"
            )

            if answer:
                connection_tuple = (ip, port)
                if connection_tuple in process_info:
                    process_name, conn = process_info[connection_tuple]
                    try:
                        process = psutil.Process(conn.pid)
                        process.terminate()
                        self.status_label.config(text=f"Process for {ip}:{port} Terminated")
                        notification.notify(
                            title="Connection Terminated",
                            message=f"Process for IP {ip}:{port} was terminated.",
                            timeout=5
                        )
                        messagebox.showinfo("Connection Terminated", f"Process for IP {ip}:{port} was successfully terminated.")
                    except Exception as e:
                        self.status_label.config(text="Failed to terminate connection")
                        messagebox.showerror("Error", f"Failed to terminate connection for {ip}:{port}.\nError: {e}")
                else:
                    self.status_label.config(text="No process found for selected IP and Port")
                    messagebox.showerror("Error", "No process found for the selected IP and Port")
            else:
                # User selected "No" or closed the dialog with "X"
                self.status_label.config(text="Kill connection operation canceled.")

    def block_ip(self):
        """Block the selected IP."""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], 'values')
            ip = values[0]

            answer = messagebox.askyesno("Confirm Block", f"Are you sure you want to block the IP {ip}?")
            
            if answer:
                os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
                self.status_label.config(text=f"{ip} has been blocked.")
                notification.notify(
                    title="IP Blocked",
                    message=f"{ip} has been blocked.",
                    timeout=5
                )
                messagebox.showinfo("IP Blocked", f"The IP {ip} has been successfully blocked.")
            else:
                # User selected "No" or closed the dialog with "X"
                self.status_label.config(text="Block IP operation canceled.")


# GUI-yə başlamaq
if __name__ == "__main__":
    global main_window
    main_window = tk.Tk()
    selector = NetworkCardSelector(main_window)
    main_window.mainloop()
