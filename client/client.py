import socket
from protocol import KeyGenerator, KeySwitch, AesEncryptDecrypt, BUFFER
from Crypto.PublicKey import RSA
from TunAdapter import create_adapter, toolkit
import re
import asyncio
import logging
import sys
from typing import Tuple, Dict


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


SERVER_ADDR = ("79.177.161.218", 50505)
ADDRESS = "10.9.0.2/24" # Client's internal IP
NAME = "vpn-tun"


CLIENT_AES_KEY: bytes = None
CLIENT_ADAPTER = None
CLIENT_SERVER_IP_ADDR = SERVER_ADDR[0]
CLIENT_SERVER_PUBLIC_KEY = None


def setup_route_table(interface_name, server_ip_addr):
    logging.info("Setting up client routing table...")
    toolkit.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=1")
    
    old_default_route = toolkit.run("ip route show 0/0")
    ipv4 = r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}"
    old_gateway_ip_addr = re.search(ipv4, old_default_route)
    
    if old_gateway_ip_addr:
        toolkit.run(f"ip route add {server_ip_addr} via {old_gateway_ip_addr.group(0)}")
    else:
        logging.error("Could not find default gateway for server bypass. Connection may fail.")

    toolkit.run(f"ip route add 0/1 dev {interface_name}")
    toolkit.run(f"ip route add 128/1 dev {interface_name}")

    toolkit.run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE")
    toolkit.run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
    toolkit.run("iptables -I FORWARD 1 -o tun0 -j ACCEPT")
    logging.info("Routing table set up successfully.")


def restore_routing_table(server_ip_address):
    logging.info("Restoring client routing table...")
    try:
        toolkit.run(f"ip route del {server_ip_address}")
        toolkit.run("ip route del 0/1")
        toolkit.run("ip route del 128/1")
        toolkit.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=0") 
        toolkit.run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE")
        toolkit.run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
        toolkit.run("iptables -D FORWARD -o tun0 -j ACCEPT")
    except Exception as e:
        logging.warning("Error during routing cleanup (rule might not have been present): %s", e)
    logging.info("Routing table restored.")


class ClientVPNDatagramProtocol(asyncio.DatagramProtocol):
    """Handles non-blocking UDP communication with the VPN server."""
    
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.handshake_step = 0 # 0: Initial, 1: Sent GETK, 2: Complete

    def connection_made(self, transport):
        self.transport = transport
        logging.info("UDP transport connected. Initiating handshake.")
        
        self.transport.sendto(b"GETK", SERVER_ADDR)
        self.handshake_step = 1

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        global CLIENT_AES_KEY, CLIENT_SERVER_PUBLIC_KEY

        if self.handshake_step == 1:
            try:
                CLIENT_SERVER_PUBLIC_KEY = RSA.import_key(data)
                
                aes_key = KeyGenerator.generate_aes()
                KeySwitch.send_aes_key(self.transport, aes_key, addr, CLIENT_SERVER_PUBLIC_KEY)
                
                CLIENT_AES_KEY = aes_key
                self.handshake_step = 2
                logging.info("Handshake complete. Starting data transfer loops.")

                self.loop.create_task(tun_reader_loop(CLIENT_ADAPTER, self.transport))

            except Exception as e:
                logging.error("Handshake error during key exchange: %s", e)
                
        elif self.handshake_step == 2 and CLIENT_AES_KEY and CLIENT_ADAPTER:
            try:
                packet = AesEncryptDecrypt.aes_decrypt(CLIENT_AES_KEY, data)
                self.loop.create_task(CLIENT_ADAPTER.write(packet))
                
                # Debug logging
                parsed_packet = toolkit.parse_packet(packet)
                toolkit.print_packet(parsed_packet, "SERVER->TUN:")
                
            except Exception as e:
                logging.error("Decryption/Write error from server: %s", e)
        else:
            logging.warning("Received unexpected data from %s", addr)



async def tun_reader_loop(adapter, transport):
    """Reads packets from the TUN adapter and sends them encrypted to the server."""
    while True:
        if not CLIENT_AES_KEY:
            await asyncio.sleep(0.1)
            continue
            
        try:
            packet = await adapter.read() 
            encrypted_packet = AesEncryptDecrypt.aes_encrypt(CLIENT_AES_KEY, packet)
            transport.sendto(encrypted_packet, SERVER_ADDR)
            
            parsed_packet = toolkit.parse_packet(packet)
            toolkit.print_packet(parsed_packet, "TUN->SERVER:")
            
        except Exception as e:
            logging.error("Error reading from TUN: %s", e)
            

async def main():
    global CLIENT_ADAPTER
    CLIENT_ADAPTER = await create_adapter(ADDRESS, NAME)
    setup_route_table(NAME, CLIENT_SERVER_IP_ADDR)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientVPNDatagramProtocol(loop),
        remote_addr=SERVER_ADDR) 
    
    try:
        # Keep the main task running indefinitely until cancelled (Ctrl+C)
        await asyncio.Future() 
    
    except asyncio.CancelledError:
        pass
        
    finally:
        # Clean up resources on exit
        if transport: transport.close()
        restore_routing_table(CLIENT_SERVER_IP_ADDR)
        logging.info("Client shutdown complete.")
        sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error("An unhandled error occurred in main: %s", e)