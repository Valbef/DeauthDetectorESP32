#!/usr/bin/env python3

import csv
import os
import signal
import subprocess
import threading
import time

from collections import defaultdict, deque
from datetime import datetime

from esp32_capture import esp32_capture

from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from scapy.layers.dot11 import (Dot11, Dot11Deauth, RadioTap )
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP


# =========================================================
# CONFIGURACIÓN
# =========================================================

DEAUTH_THRESHOLD = 20
WINDOW_SECONDS = 5

# Número de estaciones distintas para clasificar
# una ráfaga como multicliente.
MULTI_CLIENT_THRESHOLD = 3

DETECTION_LOG = "detections.csv"
DEAUTH_LOG = "deauths.csv"

CHANNEL_DWELL = 0.5

MAX_FRAME_SIZE = 1600

# Evita que una captura PCAP crezca indefinidamente
# en memoria.
#
# None = sin límite.
MAX_CAPTURE_PACKETS = None


CHANNELS_24 = [
    1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14
]

CHANNELS_5 = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112,
    116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161
]


# =========================================================
# ESTADO GLOBAL
# =========================================================

running = True

capture_enabled = False
capture_packets = []
capture_filename = None

capture_lock = threading.Lock()

channel_state = {
    "channel": None
}

mac_to_ip = {}

# ---------------------------------------------------------
# Eventos:
#
# clave:
#     (sender, bssid)
#
# valor:
#     deque de eventos
#
# Cada evento:
#     (timestamp, receiver, channel, rssi, reason)
# ---------------------------------------------------------

deauth_events = defaultdict(deque)

# Última alerta generada para evitar spam.
last_alert = {}


# =========================================================
# UTILIDADES
# =========================================================

def normalize_mac(value):

    if not value:
        return None

    return str(value).upper()


def get_ip(mac):

    if not mac:
        return "desconocida"

    return mac_to_ip.get(
        normalize_mac(mac),
        "desconocida"
    )


def get_rssi(packet):

    """
    Obtiene RSSI de distintas fuentes.

    ESP32:
        packet.rssi

    Scapy/Linux:
        packet.dBm_AntSignal
        packet.dBm
        packet.rssi
    """

    attributes = (
        "rssi",
        "dBm_AntSignal",
        "dBm"
    )

    for attribute in attributes:

        value = getattr(
            packet,
            attribute,
            None
        )

        if value is not None:

            try:
                return int(value)

            except (TypeError, ValueError):
                pass

    return None


def get_packet_channel(packet):

    """
    Intenta obtener el canal de un paquete.

    ESP32:
        packet.channel

    Linux/Scapy:
        packet.channel
        RadioTap.Channel
    """

    channel = getattr(
        packet,
        "channel",
        None
    )

    if channel is not None:

        try:
            return int(channel)

        except (TypeError, ValueError):
            pass

    return None


# =========================================================
# DETERMINAR BSSID
# =========================================================

def determine_bssid(wifi):

    addr1 = normalize_mac(
        wifi.addr1
    )

    addr2 = normalize_mac(
        wifi.addr2
    )

    addr3 = normalize_mac(
        wifi.addr3
    )

    try:

        flags = int(
            wifi.FCfield
        )

    except Exception:

        flags = 0

    to_ds = bool(
        flags & 0x1
    )

    from_ds = bool(
        flags & 0x2
    )

    # -----------------------------------------------------
    # Gestión:
    #
    # Beacon
    # Probe
    # Authentication
    # Deauthentication
    # Disassociation
    #
    # Normalmente addr3 = BSSID.
    # -----------------------------------------------------

    if not to_ds and not from_ds:

        if addr3:
            return addr3

        if addr2:
            return addr2

        return addr1

    # -----------------------------------------------------
    # STA -> AP
    #
    # addr1 = BSSID
    # -----------------------------------------------------

    if to_ds and not from_ds:

        if addr1:
            return addr1

        return addr3

    # -----------------------------------------------------
    # AP -> STA
    #
    # addr2 = BSSID
    # -----------------------------------------------------

    if from_ds and not to_ds:

        if addr2:
            return addr2

        return addr3

    # -----------------------------------------------------
    # WDS / casos especiales
    # -----------------------------------------------------

    return (
        addr3
        or addr2
        or addr1
    )


# =========================================================
# APRENDIZAJE PASIVO MAC -> IP
# =========================================================

def learn_ip(packet):

    # -----------------------------------------------------
    # IP
    # -----------------------------------------------------

    if packet.haslayer(IP):

        ip = packet[IP]

        if packet.haslayer(Dot11):

            wifi = packet[Dot11]

            src_mac = normalize_mac(
                wifi.addr2
            )

            dst_mac = normalize_mac(
                wifi.addr1
            )

            if src_mac:

                mac_to_ip[
                    src_mac
                ] = ip.src

            if dst_mac:

                mac_to_ip[
                    dst_mac
                ] = ip.dst

    # -----------------------------------------------------
    # ARP
    # -----------------------------------------------------

    if packet.haslayer(ARP):

        arp = packet[ARP]

        if arp.hwsrc and arp.psrc:

            mac_to_ip[
                normalize_mac(
                    arp.hwsrc
                )
            ] = arp.psrc


# =========================================================
# LIMPIAR EVENTOS ANTIGUOS
# =========================================================

def cleanup_events(now):

    empty_keys = []

    for key, events in list(
        deauth_events.items()
    ):

        while (
            events
            and
            now - events[0][0]
            > WINDOW_SECONDS
        ):

            events.popleft()

        if not events:

            empty_keys.append(
                key
            )

    for key in empty_keys:

        deauth_events.pop(
            key,
            None
        )


# =========================================================
# ESTADÍSTICAS DE UNA RÁFAGA
# =========================================================

def get_event_statistics(events):

    receivers = set()
    channels = set()
    reasons = set()
    rssis = []

    for event in events:

        (
            timestamp,
            receiver,
            channel,
            rssi,
            reason
        ) = event

        if receiver:

            receivers.add(
                receiver
            )

        if channel is not None:

            channels.add(
                channel
            )

        if reason is not None:

            reasons.add(
                reason
            )

        if rssi is not None:

            rssis.append(
                rssi
            )

    average_rssi = None

    if rssis:

        average_rssi = round(
            sum(rssis) / len(rssis),
            1
        )

    return (
        receivers,
        channels,
        reasons,
        average_rssi
    )


# =========================================================
# GUARDAR DETECCIÓN
# =========================================================

def save_detection(
    timestamp,
    channel,
    bssid,
    sender,
    sender_ip,
    receiver,
    receiver_ip,
    addr1,
    addr2,
    addr3,
    reason,
    count,
    unique_receivers,
    average_rssi,
    classification
):

    new_file = not os.path.exists(
        DETECTION_LOG
    )

    with open(
        DETECTION_LOG,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        if new_file:

            writer.writerow([
                "timestamp",
                "channel",
                "bssid",
                "sender_mac",
                "sender_ip",
                "receiver_mac",
                "receiver_ip",
                "addr1",
                "addr2",
                "addr3",
                "reason",
                "count",
                "unique_receivers",
                "average_rssi",
                "classification"
            ])

        writer.writerow([
            timestamp,
            channel,
            bssid,
            sender,
            sender_ip,
            receiver,
            receiver_ip,
            addr1,
            addr2,
            addr3,
            reason,
            count,
            unique_receivers,
            average_rssi,
            classification
        ])


# =========================================================
# GUARDAR EVENTO DEAUTH
# =========================================================

def save_deauth_event(
    timestamp,
    channel,
    bssid,
    sender,
    receiver,
    addr1,
    addr2,
    addr3,
    reason,
    rssi
):

    new_file = not os.path.exists(
        DEAUTH_LOG
    )

    with open(
        DEAUTH_LOG,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        if new_file:

            writer.writerow([
                "timestamp",
                "channel",
                "bssid",
                "sender",
                "receiver",
                "addr1",
                "addr2",
                "addr3",
                "reason",
                "rssi"
            ])

        writer.writerow([
            timestamp,
            channel,
            bssid,
            sender,
            receiver,
            addr1,
            addr2,
            addr3,
            reason,
            rssi
        ])


# =========================================================
# PROCESAR PAQUETE
# =========================================================

def channel_to_frequency(channel):
    """
    Convierte canal Wi-Fi 2.4 GHz a frecuencia MHz.

    Canales 1-13:
        2412 + (channel - 1) * 5

    Canal 14:
        2484
    """

    try:

        channel = int(channel)

    except (TypeError, ValueError):

        return None

    if channel == 14:

        return 2484

    if 1 <= channel <= 13:

        return 2412 + (
            (channel - 1) * 5
        )

    return None


def make_pcap_packet(packet):
    """
    Crea una copia del paquete con una cabecera
    RadioTap para que el PCAP conserve:

        - trama 802.11
        - canal/frecuencia
        - RSSI

    El paquete original NO se modifica.

    Devuelve:

        RadioTap / Dot11
        None si no se puede construir.
    """

    if not packet.haslayer(Dot11):

        return None

    wifi = packet[Dot11]

    channel = getattr(
        packet,
        "channel",
        None
    )

    rssi = getattr(
        packet,
        "rssi",
        None
    )

    frequency = channel_to_frequency(
        channel
    )

    # -----------------------------------------------------
    # Construir RadioTap
    # -----------------------------------------------------

    radiotap = RadioTap()

    present_fields = []

    # -----------------------------------------------------
    # Frecuencia/canal
    # -----------------------------------------------------

    if frequency is not None:

        present_fields.append(
            "Channel"
        )

        radiotap.ChannelFrequency = (
            frequency
        )

        # ChannelFlags:
        #
        # 2.4 GHz / OFDM.
        #
        # No dependemos de este campo para
        # el detector; la frecuencia es la
        # información importante.
        radiotap.ChannelFlags = 0x00A0

    # -----------------------------------------------------
    # RSSI
    # -----------------------------------------------------

    if rssi is not None:

        try:

            rssi = int(rssi)

            if -128 <= rssi <= 127:

                present_fields.append(
                    "dBm_AntSignal"
                )

                radiotap.dBm_AntSignal = (
                    rssi
                )

        except (
            TypeError,
            ValueError
        ):

            pass

    # -----------------------------------------------------
    # Presence
    # -----------------------------------------------------

    if present_fields:

        radiotap.present = (
            "+".join(present_fields)
        )

    # -----------------------------------------------------
    # Crear copia 802.11
    # -----------------------------------------------------

    wifi_copy = wifi.copy()

    return (
        radiotap /
        wifi_copy
    )


def process_packet(packet):

    global capture_packets

    if not running:

        return

    # =====================================================
    # PCAP
    # =====================================================

    if capture_enabled:

        with capture_lock:

            if (
                MAX_CAPTURE_PACKETS is None
                or
                len(capture_packets)
                < MAX_CAPTURE_PACKETS
            ):

                try:

                    pcap_packet = (
                        make_pcap_packet(
                            packet
                        )
                    )

                    if pcap_packet is not None:

                        capture_packets.append(
                            pcap_packet
                        )

                except Exception as e:

                    print(
                        f"[!] Error preparando "
                        f"paquete PCAP: {e}"
                    )

    # =====================================================
    # APRENDIZAJE IP
    # =====================================================

    try:

        learn_ip(packet)

    except Exception as e:

        print(
            f"[!] Error aprendiendo IP: {e}"
        )

    # =====================================================
    # SOLO DEAUTH
    # =====================================================

    if not packet.haslayer(
        Dot11Deauth
    ):

        return

    if not packet.haslayer(
        Dot11
    ):

        return

    wifi = packet[Dot11]

    deauth = packet[
        Dot11Deauth
    ]

    # =====================================================
    # DIRECCIONES
    # =====================================================

    addr1 = normalize_mac(
        wifi.addr1
    )

    addr2 = normalize_mac(
        wifi.addr2
    )

    addr3 = normalize_mac(
        wifi.addr3
    )

    sender = addr2

    receiver = addr1

    bssid = determine_bssid(
        wifi
    )

    # =====================================================
    # CANAL
    # =====================================================

    current_channel = (
        get_packet_channel(
            packet
        )
    )

    if current_channel is None:

        current_channel = (
            channel_state[
                "channel"
            ]
        )

    # =====================================================
    # RSSI
    # =====================================================

    rssi = get_rssi(
        packet
    )

    # =====================================================
    # REASON
    # =====================================================

    reason = getattr(
        deauth,
        "reason",
        None
    )

    # =====================================================
    # EVENTO
    # =====================================================

    now = time.time()

    cleanup_events(
        now
    )

    key = (
        sender,
        bssid
    )

    deauth_events[
        key
    ].append(
        (
            now,
            receiver,
            current_channel,
            rssi,
            reason
        )
    )

    # =====================================================
    # LIMPIAR VENTANA
    # =====================================================

    while (
        deauth_events[key]
        and
        now - deauth_events[key][0][0]
        > WINDOW_SECONDS
    ):

        deauth_events[key].popleft()

    # =====================================================
    # CONTADORES
    # =====================================================

    events = deauth_events[key]

    count = len(
        events
    )

    (
        receivers,
        channels,
        reasons,
        average_rssi
    ) = get_event_statistics(
        events
    )

    unique_receivers = len(
        receivers
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # =====================================================
    # GUARDAR CADA DEAUTH
    # =====================================================

    save_deauth_event(
        timestamp,
        current_channel,
        bssid,
        sender,
        receiver,
        addr1,
        addr2,
        addr3,
        reason,
        rssi
    )

    # =====================================================
    # IP
    # =====================================================

    sender_ip = get_ip(
        sender
    )

    receiver_ip = get_ip(
        receiver
    )

    # =====================================================
    # MOSTRAR
    # =====================================================

    print()

    print(
        f"[{timestamp}] DEAUTH"
    )

    print(
        f"  Canal:          "
        f"{current_channel or 'desconocido'}"
    )

    print(
        f"  BSSID:          "
        f"{bssid or 'no determinado'}"
    )

    print(
        f"  Emisor:         "
        f"{sender or 'desconocido'}"
    )

    print(
        f"  Emisor IP:      "
        f"{sender_ip}"
    )

    print(
        f"  Receptor:       "
        f"{receiver or 'desconocido'}"
    )

    print(
        f"  Receptor IP:    "
        f"{receiver_ip}"
    )

    print(
        f"  Reason:         "
        f"{reason if reason is not None else 'desconocido'}"
    )

    print(
        f"  RSSI:           "
        f"{rssi if rssi is not None else 'desconocido'} dBm"
    )

    print(
        "  Deauth actual:  1"
    )

    print(
        f"  Ventana {WINDOW_SECONDS}s: "
        f"{count}"
    )

    print(
        f"  Receptores:     "
        f"{unique_receivers}"
    )

    # =====================================================
    # CLASIFICACIÓN
    # =====================================================

    classification = "normal"

    if count >= DEAUTH_THRESHOLD:

        if (
            unique_receivers
            >= MULTI_CLIENT_THRESHOLD
        ):

            classification = (
                "posible_rafaga_multicliente"
            )

        else:

            classification = (
                "posible_rafaga"
            )

    # =====================================================
    # ALERTA
    # =====================================================

    if classification != "normal":

        alert_key = (
            sender,
            bssid
        )

        if (
            alert_key not in last_alert
            or
            now - last_alert[alert_key]
            > WINDOW_SECONDS
        ):

            last_alert[
                alert_key
            ] = now

            print()

            print(
                "=" * 70
            )

            print(
                "          POSIBLE RÁFAGA DE DEAUTHS"
            )

            print(
                "=" * 70
            )

            print(
                f"Clasificación: "
                f"{classification}"
            )

            print(
                f"Canal:         "
                f"{current_channel or 'desconocido'}"
            )

            print(
                f"BSSID:         "
                f"{bssid or 'no determinado'}"
            )

            print(
                f"Emisor:        "
                f"{sender or 'desconocido'}"
            )

            print(
                f"Deauth:        "
                f"{count} en {WINDOW_SECONDS}s"
            )

            print(
                f"Receptores:    "
                f"{unique_receivers}"
            )

            print(
                f"RSSI medio:    "
                f"{average_rssi if average_rssi is not None else 'desconocido'} dBm"
            )

            print(
                f"Reasons:       "
                f"{sorted(reasons)}"
            )

            print(
                "=" * 70
            )

            print()

            save_detection(
                timestamp,
                current_channel,
                bssid,
                sender,
                sender_ip,
                receiver,
                receiver_ip,
                addr1,
                addr2,
                addr3,
                reason,
                count,
                unique_receivers,
                average_rssi,
                classification
            )

# =========================================================
# CAMBIO DE CANAL LINUX
# =========================================================

def set_channel(
    interface,
    channel
):

    try:

        result = subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "set",
                "channel",
                str(channel)
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:

            print(
                f"\n[!] No se pudo cambiar "
                f"al canal {channel}:"
            )

            if result.stderr:

                print(
                    f"    {result.stderr.strip()}"
                )

            return False

        channel_state[
            "channel"
        ] = channel

        return True

    except FileNotFoundError:

        print(
            "\n[!] No se encontró 'iw'."
        )

        return False

    except Exception as e:

        print(
            f"\n[!] Error cambiando canal: {e}"
        )

        return False


# =========================================================
# CHANNEL HOPPING LINUX
# =========================================================

def channel_hopper(
    interface,
    channels
):

    while running:

        for channel in channels:

            if not running:

                break

            if set_channel(
                interface,
                channel
            ):

                print(
                    f"\r[+] Escuchando canal "
                    f"{channel}    ",
                    end="",
                    flush=True
                )

                time.sleep(
                    CHANNEL_DWELL
                )


# =========================================================
# GUARDAR CAPTURA
# =========================================================

def save_capture():

    if not capture_enabled:

        return

    if not capture_filename:

        return

    print()

    print(
        f"[+] Guardando captura en: "
        f"{capture_filename}"
    )

    try:

        with capture_lock:

            packets = list(
                capture_packets
            )

        if not packets:

            print(
                "[!] No se capturaron paquetes."
            )

            return

        wrpcap(
            capture_filename,
            packets
        )

        print(
            "[+] Captura guardada correctamente."
        )

        print(
            f"[+] Paquetes: "
            f"{len(packets)}"
        )

    except Exception as e:

        print(
            f"[!] Error guardando captura: "
            f"{e}"
        )


# =========================================================
# CTRL+C
# =========================================================

def stop_program(
    signum=None,
    frame=None
):

    global running

    if running:

        print()
        print(
            "[!] CTRL+C recibido."
        )

        print(
            "[+] Deteniendo..."
        )

        running = False


# =========================================================
# PREGUNTA S/N
# =========================================================

def ask_yes_no(question):

    while True:

        answer = input(
            f"{question} [s/n]: "
        ).strip().lower()

        if answer in (
            "s",
            "si",
            "sí",
            "y",
            "yes"
        ):

            return True

        if answer in (
            "n",
            "no"
        ):

            return False

        print(
            "[!] Responde s/n."
        )


# =========================================================
# TIPO DE INTERFAZ
# =========================================================

def get_interface_type(interface):

    try:

        result = subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "info"
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:

            return None

        for line in result.stdout.splitlines():

            line = line.strip()

            if line.startswith("type "):

                return line.split()[1]

    except Exception:

        return None

    return None


def check_interface(interface):

    interface_type = get_interface_type(
        interface
    )

    if interface_type is None:

        print(
            f"[!] No se pudo obtener información "
            f"de '{interface}'."
        )

        return False

    print(
        f"[+] Interfaz: {interface}"
    )

    print(
        f"[+] Modo: {interface_type}"
    )

    if interface_type == "monitor":

        return True

    print()

    print(
        "[!] La interfaz no está en modo monitor."
    )

    print(
        "[!] La captura 802.11 puede no funcionar."
    )

    print()

    return ask_yes_no(
        "¿Continuar?"
    )


# =========================================================
# SELECCIONAR CAPTURA
# =========================================================

def select_capture_mode():

    global capture_enabled
    global capture_filename

    capture_enabled = ask_yes_no(
        "¿Quieres guardar la captura?"
    )

    if not capture_enabled:

        capture_filename = None

        return

    while True:

        filename = input(
            "Nombre del archivo "
            "(ej. captura.pcap): "
        ).strip()

        if not filename:

            print(
                "[!] Introduce un nombre."
            )

            continue

        if "." not in filename:

            filename += ".pcap"

        capture_filename = filename

        return


# =========================================================
# SELECCIONAR CANAL
# =========================================================

def select_channel():

    print()

    print(
        "1) Canal fijo"
    )

    print(
        "2) Channel hopping"
    )

    while True:

        option = input(
            "Opción: "
        ).strip()

        if option == "1":

            while True:

                value = input(
                    "Canal (1-14): "
                ).strip()

                try:

                    channel = int(
                        value
                    )

                    if 1 <= channel <= 14:

                        return (
                            "fixed",
                            channel,
                            None
                        )

                except ValueError:

                    pass

                print(
                    "[!] Canal no válido."
                )

        elif option == "2":

            print()

            print(
                "1) 2.4 GHz"
            )

            print(
                "2) 5 GHz (interfaz Linux)"
            )

            print(
                "3) 2.4 + 5 GHz (interfaz Linux)"
            )

            print()

            band = input(
                "Opción: "
            ).strip()

            if band == "1":

                return (
                    "hopping",
                    None,
                    CHANNELS_24
                )

            if band == "2":

                return (
                    "hopping",
                    None,
                    CHANNELS_5
                )

            if band == "3":

                return (
                    "hopping",
                    None,
                    CHANNELS_24 + CHANNELS_5
                )

        print(
            "[!] Opción no válida."
        )


# =========================================================
# CAPTURA
# =========================================================

def start_capture(
    interface,
    mode,
    channel=None,
    channels=None
):

    global running

    running = True

    print()
    print(
        "=" * 70
    )

    print(
        "                 DEAUTH DETECTOR"
    )

    print(
        "=" * 70
    )

    print()

    print(
        f"Fuente: {interface}"
    )

    print(
        "Modo: PASIVO"
    )

    print(
        f"Guardar PCAP: "
        f"{'SÍ' if capture_enabled else 'NO'}"
    )

    # =====================================================
    # ESP32
    # =====================================================

    if interface.upper() == "ESP32":

        print()
        print(
            "[+] ESP32-WROOM-32"
        )

        print(
            "[+] Banda: 2.4 GHz"
        )

        port = input(
            "Puerto serie "
            "(ej. /dev/ttyUSB0): "
        ).strip()

        if not port:

            print(
                "[!] Puerto no indicado."
            )

            return

        print()
        print(
            "Baudrate: 921600"
        )

        if mode == "fixed":

            print(
                f"Canal: {channel}"
            )

        else:

            channels = [
                c
                for c in channels
                if 1 <= c <= 14
            ]

            print(
                f"Canales: {channels}"
            )

        input(
            "\nPulsa ENTER para comenzar..."
        )

        try:

            esp32_capture(
                port=port,
                baudrate=921600,
                callback=process_packet,
                channel_state=channel_state,
                running=lambda: running,
                channels=(
                    channels
                    if mode == "hopping"
                    else None
                ),
                dwell=CHANNEL_DWELL,
                fixed_channel=(
                    channel
                    if mode == "fixed"
                    else None
                )
            )

        except KeyboardInterrupt:

            stop_program()

        finally:

            running = False

            save_capture()

            print(
                "[+] Captura ESP32 detenida."
            )

        return

    # =====================================================
    # LINUX
    # =====================================================

    if mode == "fixed":

        if not set_channel(
            interface,
            channel
        ):

            return

    hopper_thread = None

    if mode == "hopping":

        hopper_thread = threading.Thread(
            target=channel_hopper,
            args=(
                interface,
                channels
            ),
            daemon=True
        )

        hopper_thread.start()

    print()

    input(
        "Pulsa ENTER para comenzar..."
    )

    try:

        sniff(
            iface=interface,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        stop_program()

    except PermissionError:

        print(
            "[!] Permiso denegado."
        )

        running = False

    except Exception as e:

        print(
            f"[!] Error de captura: {e}"
        )

        running = False

    finally:

        running = False

        save_capture()

        print(
            "[+] Captura detenida."
        )


# =========================================================
# MAIN
# =========================================================

def main():

    signal.signal(
        signal.SIGINT,
        stop_program
    )

    print()
    print(
        "=" * 70
    )

    print(
        "             DETECTOR PASIVO DE DEAUTHS"
    )

    print(
        "=" * 70
    )

    print()

    interface = input(
        "Interfaz "
        "(wlan0/wlan1/ESP32): "
    ).strip()

    if not interface:

        return

    if interface.upper() != "ESP32":

        if not check_interface(
            interface
        ):

            return

    select_capture_mode()

    mode, channel, channels = (
        select_channel()
    )

    # -----------------------------------------------------
    # ESP32 solamente 2.4 GHz
    # -----------------------------------------------------

    if (
        interface.upper() == "ESP32"
        and channels
    ):

        channels = [
            c
            for c in channels
            if 1 <= c <= 14
        ]

        if not channels:

            print(
                "[!] No hay canales 2.4 GHz."
            )

            return

    print()

    print(
        "=" * 70
    )

    print(
        "CONFIGURACIÓN"
    )

    print(
        "=" * 70
    )

    print(
        f"Fuente: {interface}"
    )

    if interface.upper() == "ESP32":

        print(
            "Banda: 2.4 GHz"
        )

    if mode == "fixed":

        print(
            f"Canal: {channel}"
        )

    else:

        print(
            f"Canales: {channels}"
        )

    print(
        f"PCAP: "
        f"{'Sí' if capture_enabled else 'No'}"
    )

    print()

    if not ask_yes_no(
        "¿Quieres empezar?"
    ):

        return

    start_capture(
        interface,
        mode,
        channel,
        channels
    )


# =========================================================
# INICIO
# =========================================================

if __name__ == "__main__":

    main()
