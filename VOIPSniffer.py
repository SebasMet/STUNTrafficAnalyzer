from scapy.all import sniff, raw, Packet
from scapy.layers.inet import UDP, IP
from datetime import datetime
import socket

BINDING_SUCCESS_RESPONSE_HEX = '0101'
STUN_MAGIC_COOKIE_HEX = '2112a442'

def get_internal_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def is_binding_success_response(packet):
    message_type_bytes = raw(packet[UDP].payload)[:2]  
    message_type_hex = message_type_bytes.hex()
    return message_type_hex == BINDING_SUCCESS_RESPONSE_HEX

def has_stun_magic_cookie(packet):
    if UDP in packet and len(packet[UDP].payload) >= 20:
        payload_bytes = raw(packet[UDP].payload)
        payload_hex = payload_bytes.hex()
        return STUN_MAGIC_COOKIE_HEX in payload_hex
    return False

def print_all(packet: Packet, now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")):
    if UDP in packet and IP in packet:
        if(has_stun_magic_cookie(packet) and is_binding_success_response(packet)):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"Time: {now}")
            if(src_ip == get_internal_ip()):
                print(f"IP Adress of caller: {dst_ip}")
            else:
                print(f"IP Adress of caller: {src_ip}")
  
print ("____   ___________  ._____________    _________      .__  _____  _____             ")
print ("\   \ /   /\   _  \ |   \______   \  /   _____/ ____ |__|/ ____\/ ____\___________ ")
print (" \   Y   / /  /_\  \|   ||     ___/  \_____  \ /    \|  \   __\\   __\/ __ \_  __ \ ")
print ("  \     /  \  \_/   \   ||    |      /        \   |  \  ||  |   |  | \  ___/|  | \/")
print ("   \___/    \_____  /___||____|     /_______  /___|  /__||__|   |__|  \___  >__|   ")
print ("                  \/                        \/     \/                     \/       ")
print ("\n\n\n\nThe creators, developers, and distributors of this tool disclaim any liability for misuse of the software or any damages that may arise from its use. The User assumes \033[1mfull\033[0m responsibility and liability for any consequences of their actions when using the tool. \n\n")

sniff(prn=print_all, store=0)

