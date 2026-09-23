from scapy.all import sniff


def live_capture(interface, callback):
    """
    Captura pasiva.
    No transmite paquetes.
    """

    print(f"[+] Interfaz: {interface}")
    print("[+] Modo: CAPTURA PASIVA")
    print("[+] Esperando tramas 802.11...")
    print("[+] Ctrl+C para salir\n")

    sniff(
        iface=interface,
        prn=callback,
        store=False
    )
