import socket
import sys

HOST = '127.0.0.1'
PORT = 4445  # On utilise 4445 pour éviter les conflits Windows

# Configuration de la fausse réponse (128 octets de zéros)
response_payload = bytearray([0] * 128)

# Logique de smb.nim : il lit response[72]
# Si (securityMode & 0x02) == 0x02, alors le signing est requis.
# On injecte 0x02 (ou 0x03) à l'index 72 pour simuler "SMB Signing Required"
response_payload[72] = 0x02 

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[+] Faux serveur SMB en écoute sur {HOST}:{PORT}")
        print("[*] En attente que NimScope se connecte...")
    except Exception as e:
        print(f"[-] Impossible de démarrer le serveur : {e}")
        sys.exit(1)

    try:
        while True:
            conn, addr = server.accept()
            print(f"\n[+] Connexion reçue de {addr[0]}:{addr[1]}")
            
            # Reçoit le paquet 'smbNegotiatePacket' envoyé par NimScope
            data = conn.recv(1024)
            if data:
                print(f"[*] Reçu {len(data)} octets (Requête de négociation de NimScope)")
                
                # Renvoie la réponse truquée
                conn.sendall(response_payload)
                print("[+] Fausse réponse SMB envoyée (Index 72 = 0x02)")
                
            conn.close()
            print("[*] Connexion fermée. Prêt pour un autre test.")
    except KeyboardInterrupt:
        print("\n[-] Arrêt du serveur.")
    finally:
        server.close()

if __name__ == '__main__':
    run_server()
