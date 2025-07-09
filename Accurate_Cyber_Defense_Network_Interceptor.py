import sys
import socket
import threading
import time
import dpkt
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import platform
import psutil
from datetime import datetime

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Network Intercepter")
        self.root.geometry("1200x800")
        self.root.configure(bg="#002200")  # Dark green theme
        
        # Variables
        self.target_ip = tk.StringVar()
        self.is_monitoring = False
        self.packet_count = 0
        self.threat_count = 0
        self.packet_data = []
        self.protocol_stats = defaultdict(int)
        self.threat_stats = defaultdict(int)
        self.start_time = None
        
        # Create menu
        self.create_menu()
        
        # Create main interface
        self.create_interface()
        
        # Initialize socket
        self.socket = None
        self.init_socket()
        
        # Start UI update thread
        self.update_ui()
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Report", command=self.save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Packet Log", command=self.show_packet_log)
        view_menu.add_command(label="Protocol Stats", command=self.show_protocol_stats)
        view_menu.add_command(label="Threat Stats", command=self.show_threat_stats)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Port Scanner", command=self.show_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.show_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Theme Settings", command=self.show_theme_settings)
        settings_menu.add_command(label="Alert Settings", command=self.show_alert_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_interface(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg="#003300")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = tk.Frame(main_frame, bg="#004400", bd=2, relief=tk.RIDGE)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(control_frame, text="Target IP:", bg="#004400", fg="white").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(control_frame, textvariable=self.target_ip, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        self.start_btn = tk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring, bg="#006600", fg="white")
        self.start_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.stop_btn = tk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED, bg="#660000", fg="white")
        self.stop_btn.grid(row=0, column=3, padx=5, pady=5)
        
        # Stats panel
        stats_frame = tk.Frame(main_frame, bg="#004400", bd=2, relief=tk.RIDGE)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(stats_frame, text="Packets Captured:", bg="#004400", fg="white").grid(row=0, column=0, padx=5, pady=5)
        self.packet_label = tk.Label(stats_frame, text="0", bg="#004400", fg="white")
        self.packet_label.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(stats_frame, text="Threats Detected:", bg="#004400", fg="white").grid(row=0, column=2, padx=5, pady=5)
        self.threat_label = tk.Label(stats_frame, text="0", bg="#004400", fg="white")
        self.threat_label.grid(row=0, column=3, padx=5, pady=5)
        
        tk.Label(stats_frame, text="Monitoring Time:", bg="#004400", fg="white").grid(row=0, column=4, padx=5, pady=5)
        self.time_label = tk.Label(stats_frame, text="00:00:00", bg="#004400", fg="white")
        self.time_label.grid(row=0, column=5, padx=5, pady=5)
        
        # Visualization frame
        vis_frame = tk.Frame(main_frame, bg="#005500")
        vis_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Protocol distribution pie chart
        self.protocol_fig, self.protocol_ax = plt.subplots(figsize=(5, 4), facecolor='#003300')
        self.protocol_ax.set_title("Protocol Distribution", color='white')
        self.protocol_fig.patch.set_facecolor('#003300')
        self.protocol_ax.set_facecolor('#003300')
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, master=vis_frame)
        self.protocol_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Threat distribution bar chart
        self.threat_fig, self.threat_ax = plt.subplots(figsize=(5, 4), facecolor='#003300')
        self.threat_ax.set_title("Threat Distribution", color='white')
        self.threat_fig.patch.set_facecolor('#003300')
        self.threat_ax.set_facecolor('#003300')
        self.threat_canvas = FigureCanvasTkAgg(self.threat_fig, master=vis_frame)
        self.threat_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Log frame
        log_frame = tk.Frame(main_frame, bg="#004400", bd=2, relief=tk.RIDGE)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(log_frame, bg="#001100", fg="white", wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = tk.Scrollbar(self.log_text)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.log_text.yview)
        
        # Add initial log message
        self.log("Cyber Security Tool initialized. Ready to monitor network traffic.")
    
    def init_socket(self):
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.socket.bind(('0.0.0.0', 0))
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.log("Socket initialized for packet capture.")
        except Exception as e:
            self.log(f"Error initializing socket: {str(e)}")
            messagebox.showerror("Error", f"Failed to initialize socket: {str(e)}")
    
    def start_monitoring(self):
        target_ip = self.target_ip.get()
        if not target_ip:
            messagebox.showwarning("Warning", "Please enter a target IP address")
            return
        
        self.is_monitoring = True
        self.packet_count = 0
        self.threat_count = 0
        self.packet_data = []
        self.protocol_stats = defaultdict(int)
        self.threat_stats = defaultdict(int)
        self.start_time = datetime.now()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()
        
        self.log(f"Started monitoring traffic for IP: {target_ip}")
    
    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("Stopped monitoring network traffic.")
    
    def capture_packets(self):
        target_ip = self.target_ip.get()
        
        while self.is_monitoring:
            try:
                # Capture packet
                packet, addr = self.socket.recvfrom(65535)
                src_ip = addr[0]
                
                # Only process packets to/from target IP if specified
                if target_ip and target_ip not in [src_ip]:
                    continue
                
                # Parse packet
                self.packet_count += 1
                packet_info = self.parse_packet(packet)
                self.packet_data.append(packet_info)
                
                # Update protocol stats
                protocol = packet_info.get('protocol', 'Unknown')
                self.protocol_stats[protocol] += 1
                
                # Check for threats
                threat_detected, threat_type = self.detect_threat(packet_info)
                if threat_detected:
                    self.threat_count += 1
                    self.threat_stats[threat_type] += 1
                    self.log(f"THREAT DETECTED: {threat_type} - {packet_info}")
                
                # Update UI periodically (actual updates happen in update_ui)
                if self.packet_count % 10 == 0:
                    time.sleep(0.1)  # Prevent UI freeze
            
            except Exception as e:
                self.log(f"Error capturing packet: {str(e)}")
                time.sleep(1)
    
    def parse_packet(self, packet):
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            
            packet_info = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'src_ip': socket.inet_ntoa(ip.src),
                'dst_ip': socket.inet_ntoa(ip.dst),
                'protocol': ip.p,
                'length': len(packet)
            }
            
            # Check for TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp.sport
                packet_info['dst_port'] = tcp.dport
                packet_info['flags'] = self.get_tcp_flags(tcp.flags)
            
            # Check for UDP
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp.sport
                packet_info['dst_port'] = udp.dport
            
            # Check for ICMP
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                packet_info['protocol'] = 'ICMP'
                packet_info['type'] = icmp.type
            
            self.log(f"Packet captured: {packet_info}")
            return packet_info
        
        except Exception as e:
            self.log(f"Error parsing packet: {str(e)}")
            return {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'error': str(e),
                'raw_packet': packet.hex()
            }
    
    def get_tcp_flags(self, flags):
        flag_names = []
        if flags & dpkt.tcp.TH_FIN:
            flag_names.append('FIN')
        if flags & dpkt.tcp.TH_SYN:
            flag_names.append('SYN')
        if flags & dpkt.tcp.TH_RST:
            flag_names.append('RST')
        if flags & dpkt.tcp.TH_PUSH:
            flag_names.append('PSH')
        if flags & dpkt.tcp.TH_ACK:
            flag_names.append('ACK')
        if flags & dpkt.tcp.TH_URG:
            flag_names.append('URG')
        return '/'.join(flag_names) if flag_names else 'None'
    
    def detect_threat(self, packet_info):
        # Simple threat detection logic - expand this for real-world use
        protocol = packet_info.get('protocol', '')
        
        # SYN flood detection
        if protocol == 'TCP' and 'SYN' in packet_info.get('flags', '') and not 'ACK' in packet_info.get('flags', ''):
            if self.protocol_stats['TCP'] > 100:  # Arbitrary threshold
                return True, 'SYN Flood'
        
        # Port scan detection
        if protocol == 'TCP' and 'SYN' in packet_info.get('flags', '') and not 'ACK' in packet_info.get('flags', ''):
            dst_port = packet_info.get('dst_port', 0)
            if dst_port < 1024:  # Well-known ports
                return True, 'Port Scan Attempt'
        
        # ICMP flood detection
        if protocol == 'ICMP' and packet_info.get('type', 0) == 8:  # Echo request
            if self.protocol_stats['ICMP'] > 50:  # Arbitrary threshold
                return True, 'ICMP Flood'
        
        # UDP flood detection
        if protocol == 'UDP':
            if self.protocol_stats['UDP'] > 200:  # Arbitrary threshold
                return True, 'UDP Flood'
        
        return False, ''
    
    def update_ui(self):
        # Update stats labels
        self.packet_label.config(text=str(self.packet_count))
        self.threat_label.config(text=str(self.threat_count))
        
        # Update monitoring time
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            self.time_label.config(text=str(elapsed).split('.')[0])
        
        # Update charts
        self.update_protocol_chart()
        self.update_threat_chart()
        
        # Schedule next update
        self.root.after(1000, self.update_ui)
    
    def update_protocol_chart(self):
        self.protocol_ax.clear()
        
        if self.protocol_stats:
            labels = list(self.protocol_stats.keys())
            sizes = list(self.protocol_stats.values())
            
            # Use green shades for the theme
            colors = ['#00aa00', '#007700', '#005500', '#003300', '#001100']
            
            self.protocol_ax.pie(sizes, labels=labels, autopct='%1.1f%%', 
                               startangle=90, colors=colors[:len(labels)])
            self.protocol_ax.set_title("Protocol Distribution", color='white')
            self.protocol_ax.set_facecolor('#003300')
            self.protocol_canvas.draw()
    
    def update_threat_chart(self):
        self.threat_ax.clear()
        
        if self.threat_stats:
            labels = list(self.threat_stats.keys())
            values = list(self.threat_stats.values())
            
            # Use red shades for threats
            colors = ['#ff0000', '#cc0000', '#990000', '#660000']
            
            if labels:
                bars = self.threat_ax.bar(labels, values, color=colors[:len(labels)])
                self.threat_ax.set_title("Threat Distribution", color='white')
                self.threat_ax.set_facecolor('#003300')
                
                # Add value labels on top of bars
                for bar in bars:
                    height = bar.get_height()
                    self.threat_ax.text(bar.get_x() + bar.get_width()/2., height,
                                      '%d' % int(height),
                                      ha='center', va='bottom', color='white')
                
                self.threat_canvas.draw()
    
    def log(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        self.log_text.insert(tk.END, timestamp + message + "\n")
        self.log_text.see(tk.END)
    
    def save_report(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                title="Save Report"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(f"Cyber Security Monitoring Report\n")
                    f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"\nSummary:\n")
                    f.write(f"Total Packets Captured: {self.packet_count}\n")
                    f.write(f"Total Threats Detected: {self.threat_count}\n")
                    f.write(f"Monitoring Duration: {str(datetime.now() - self.start_time).split('.')[0] if self.start_time else 'N/A'}\n")
                    
                    f.write(f"\nProtocol Distribution:\n")
                    for protocol, count in self.protocol_stats.items():
                        f.write(f"{protocol}: {count} packets\n")
                    
                    f.write(f"\nThreat Distribution:\n")
                    for threat, count in self.threat_stats.items():
                        f.write(f"{threat}: {count} occurrences\n")
                    
                    f.write(f"\nPacket Log (last 100 packets):\n")
                    for packet in self.packet_data[-100:]:
                        f.write(f"{packet.get('timestamp', 'N/A')} - {packet}\n")
                
                self.log(f"Report saved to: {filename}")
                messagebox.showinfo("Success", "Report saved successfully")
        
        except Exception as e:
            self.log(f"Error saving report: {str(e)}")
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    # Menu command implementations
    def show_packet_log(self):
        self.log("Displaying packet log...")
    
    def show_protocol_stats(self):
        self.log("Displaying protocol statistics...")
    
    def show_threat_stats(self):
        self.log("Displaying threat statistics...")
    
    def show_port_scanner(self):
        self.log("Opening port scanner tool...")
        # Implement port scanner functionality
    
    def show_packet_analyzer(self):
        self.log("Opening packet analyzer tool...")
        # Implement packet analyzer functionality
    
    def show_theme_settings(self):
        self.log("Opening theme settings...")
        # Implement theme settings
    
    def show_alert_settings(self):
        self.log("Opening alert settings...")
        # Implement alert settings
    
    def show_user_guide(self):
        self.log("Displaying user guide...")
        messagebox.showinfo("User Guide", "This is a cyber security monitoring tool that captures and analyzes network traffic.")
    
    def show_about(self):
        about_text = """
        Ian Carter Kulani
        E-mail:iancarterkulani@gmail.com
        Cyber Security Monitoring Tool
        Version 1.0
        
        Features:
        - Real-time packet capture
        - Threat detection
        - Protocol analysis
        - Visual statistics
        
        Created with Python
        """
        messagebox.showinfo("About", about_text)

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()