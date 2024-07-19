import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from scapy.all import *
import threading

class NetworkSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        
        self.packet_display = scrolledtext.ScrolledText(root, width=100, height=20)
        self.packet_display.pack(padx=10, pady=10)
        
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)
        
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)
        
        self.sniffing = False
        self.stop_sniffing_event = threading.Event()
        self.sniffer_thread = None

    def start_sniffing(self):
        if self.sniffing:
            messagebox.showinfo("Info", "Already sniffing!")
            return
        
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        if not self.sniffing:
            return
        
        self.sniffing = False
        self.stop_sniffing_event.set()  
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        try:
            sniff(prn=self.process_packet, stop_filter=self.should_stop_sniffing, store=False)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def process_packet(self, packet):
        try:
            if IP in packet:
                pkt_summary = f"Source: {packet[IP].src} -> Destination: {packet[IP].dst} / Protocol: {packet[IP].proto}\n"
                self.packet_display.insert(tk.END, pkt_summary)
                self.packet_display.see(tk.END)
        except Exception as e:
            print(f"Exception processing packet: {str(e)}")

        if self.stop_sniffing_event.is_set():
            return True  

    def should_stop_sniffing(self, packet):
        return self.stop_sniffing_event.is_set()

def main():
    root = tk.Tk()
    app = NetworkSniffer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
