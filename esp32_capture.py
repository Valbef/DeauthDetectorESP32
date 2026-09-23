#!/usr/bin/env python3

import struct
import threading
import time

import serial

from scapy.layers.dot11 import Dot11, Dot11Deauth


# =========================================================
# CONFIGURACIÓN
# =========================================================

MAGIC = b"\xAA\x55"

MAX_FRAME_SIZE = 1600

SERIAL_TIMEOUT = 1.0


# =========================================================
# LECTURA EXACTA
# =========================================================

def read_exact(ser, size):
    """
    Lee exactamente 'size' bytes del puerto serie.

    Devuelve:
        bytes   -> si se recibieron todos los bytes
        None    -> si hubo timeout / puerto cerrado
    """

    data = bytearray()

    while len(data) < size:

        chunk = ser.read(
            size - len(data)
        )

        if not chunk:
            return None

        data.extend(chunk)

    return bytes(data)


# =========================================================
# SINCRONIZACIÓN AA 55
# =========================================================

def sync_magic(ser):
    """
    Busca la secuencia:

        AA 55

    en el flujo serie.

    Al devolver True, los dos bytes MAGIC
    ya han sido consumidos.
    """

    previous = None

    while True:

        byte = ser.read(1)

        if not byte:
            return False

        current = byte[0]

        if (
            previous == 0xAA
            and current == 0x55
        ):
            return True

        previous = current


# =========================================================
# CAMBIO DE CANAL
# =========================================================

def esp32_set_channel(
    ser,
    channel
):
    """
    Envía al ESP32:

        C<canal>\\n

    Ejemplo:

        C6\\n
    """

    channel = int(channel)

    if not 1 <= channel <= 14:
        raise ValueError(
            f"Canal ESP32 inválido: {channel}"
        )

    command = (
        f"C{channel}\n"
    )

    ser.write(
        command.encode("ascii")
    )

    ser.flush()


# =========================================================
# CHANNEL HOPPING
# =========================================================

def esp32_channel_hopper(
    ser,
    channels,
    dwell,
    channel_state,
    running
):
    """
    Cambia periódicamente el canal del ESP32.

    El ESP32 solamente admite 2.4 GHz:
        1 - 14
    """

    while running():

        for channel in channels:

            if not running():
                break

            try:

                esp32_set_channel(
                    ser,
                    channel
                )

                channel_state[
                    "channel"
                ] = channel

                print(
                    f"\r[+] ESP32 canal "
                    f"{channel}    ",
                    end="",
                    flush=True
                )

                time.sleep(
                    dwell
                )

            except Exception as e:

                print()

                print(
                    f"[!] Error cambiando "
                    f"canal ESP32: {e}"
                )

                return


# =========================================================
# CAPTURA ESP32
# =========================================================

def esp32_capture(
    port,
    baudrate,
    callback,
    channel_state,
    running,
    channels=None,
    dwell=0.5,
    fixed_channel=None
):
    """
    Captura tramas 802.11 procedentes del ESP32.

    Formato enviado por el firmware:

        AA 55
        channel     1 byte
        length      2 bytes LE
        timestamp   4 bytes LE
        rssi        1 byte signed
        frame       length bytes

    Los AA 55 se consumen durante sync_magic(),
    por lo que posteriormente se leen 8 bytes
    de cabecera.
    """

    print(
        f"[+] Puerto ESP32: {port}"
    )

    print(
        f"[+] Baudrate: {baudrate}"
    )

    # -----------------------------------------------------
    # ABRIR PUERTO
    # -----------------------------------------------------

    try:

        ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            timeout=SERIAL_TIMEOUT
        )

    except Exception as e:

        print(
            f"[!] No se pudo abrir "
            f"{port}: {e}"
        )

        return False

    hopper_thread = None

    try:

        # -------------------------------------------------
        # Esperar a que el ESP32 se estabilice
        # -------------------------------------------------

        time.sleep(2)

        # -------------------------------------------------
        # Descartar datos antiguos
        # -------------------------------------------------

        ser.reset_input_buffer()

        # -------------------------------------------------
        # CANAL FIJO
        # -------------------------------------------------

        if fixed_channel is not None:

            if not 1 <= int(fixed_channel) <= 14:

                print(
                    f"[!] Canal ESP32 inválido: "
                    f"{fixed_channel}"
                )

                return False

            esp32_set_channel(
                ser,
                fixed_channel
            )

            channel_state[
                "channel"
            ] = int(fixed_channel)

        # -------------------------------------------------
        # CHANNEL HOPPING
        # -------------------------------------------------

        elif channels:

            valid_channels = [
                int(channel)
                for channel in channels
                if 1 <= int(channel) <= 14
            ]

            if not valid_channels:

                print(
                    "[!] No hay canales válidos "
                    "para el ESP32."
                )

                return False

            hopper_thread = threading.Thread(
                target=esp32_channel_hopper,
                args=(
                    ser,
                    valid_channels,
                    dwell,
                    channel_state,
                    running
                ),
                daemon=True
            )

            hopper_thread.start()

        # -------------------------------------------------
        # ESTADO
        # -------------------------------------------------

        print()
        print(
            "[+] ESP32 conectado."
        )

        print(
            "[+] Esperando tramas 802.11..."
        )

        print()

        # =================================================
        # BUCLE PRINCIPAL
        # =================================================

        while running():

            # ---------------------------------------------
            # Buscar AA 55
            # ---------------------------------------------

            if not sync_magic(ser):
                continue

            # ---------------------------------------------
            # CABECERA
            #
            # Después de AA 55:
            #
            # channel     1
            # length      2
            # timestamp   4
            # rssi        1
            #
            # TOTAL = 8 bytes
            # ---------------------------------------------

            header = read_exact(
                ser,
                8
            )

            if header is None:
                break

            # ---------------------------------------------
            # CHANNEL
            # ---------------------------------------------

            channel = header[0]

            # ---------------------------------------------
            # LENGTH
            # ---------------------------------------------

            length = struct.unpack(
                "<H",
                header[1:3]
            )[0]

            # ---------------------------------------------
            # TIMESTAMP
            # ---------------------------------------------

            timestamp = struct.unpack(
                "<I",
                header[3:7]
            )[0]

            # ---------------------------------------------
            # RSSI
            #
            # Firmware:
            #
            # int8_t
            # ---------------------------------------------

            rssi = struct.unpack(
                "<b",
                header[7:8]
            )[0]

            # ---------------------------------------------
            # VALIDACIÓN DEL CANAL
            # ---------------------------------------------

            if not 1 <= channel <= 14:

                print(
                    f"\n[!] Canal inválido "
                    f"recibido del ESP32: {channel}"
                )

                # No sabemos con seguridad dónde
                # comienza el siguiente frame.
                #
                # Continuamos buscando MAGIC.
                continue

            # ---------------------------------------------
            # VALIDACIÓN DE LONGITUD
            # ---------------------------------------------

            if length == 0:

                continue

            if length > MAX_FRAME_SIZE:

                print(
                    f"\n[!] Longitud inválida "
                    f"recibida del ESP32: {length}"
                )

                # El firmware tampoco debería enviar
                # una longitud superior a MAX_FRAME_SIZE.
                #
                # No intentamos leerla.
                continue

            # ---------------------------------------------
            # FRAME 802.11
            # ---------------------------------------------

            frame = read_exact(
                ser,
                length
            )

            if frame is None:
                break

            # ---------------------------------------------
            # SCAPY
            #
            # El firmware ESP32 envía directamente
            # packet->payload, es decir, la trama 802.11.
            #
            # NO hacemos:
            #
            # RadioTap() / Dot11(frame)
            #
            # porque el ESP32 no está enviando una
            # cabecera RadioTap.
            # ---------------------------------------------

            try:

                packet = Dot11(
                    frame
                )

            except Exception as e:

                print(
                    f"\n[!] Error decodificando "
                    f"trama 802.11: {e}"
                )

                continue

            # ---------------------------------------------
            # VALIDACIÓN BÁSICA
            # ---------------------------------------------

            if not packet.haslayer(Dot11):

                continue

            # ---------------------------------------------
            # METADATA DEL ESP32
            # ---------------------------------------------

            packet.channel = channel

            packet.rssi = rssi

            packet.esp32_timestamp = (
                timestamp
            )

            packet.capture_time = (
                time.time()
            )

            # Mantener el estado global sincronizado
            # con el canal recibido.
            channel_state[
                "channel"
            ] = channel

            # ---------------------------------------------
            # CALLBACK
            #
            # DeauthDetector.py recibe solamente
            # las tramas deauth.
            # ---------------------------------------------

            try:

                if packet.haslayer(
                    Dot11Deauth
                ):

                    callback(
                        packet
                    )

            except Exception as e:

                print()

                print(
                    f"[!] Error en callback: "
                    f"{e}"
                )

    except KeyboardInterrupt:

        pass

    except Exception as e:

        print(
            f"[!] Error capturando ESP32: "
            f"{e}"
        )

        return False

    finally:

        # -------------------------------------------------
        # Detener hopper
        # -------------------------------------------------

        if hopper_thread:

            hopper_thread.join(
                timeout=0.2
            )

        # -------------------------------------------------
        # Cerrar puerto
        # -------------------------------------------------

        try:

            ser.close()

        except Exception:
            pass

    return True
