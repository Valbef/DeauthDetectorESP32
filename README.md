# DeauthDetectorESP32
Herramienta de deteccion de tramas de deauth para Linux 
con compatibilidad con modulos wifi 2,4G Y 5G con modo monitor
y ESP32-WROOM-32 (solo 2,4G). 

Tiene opcion de captura de archivos PCAP compatibles con Wireshark.

((Esta herramienta esta en fase de desarrollo))


Descarga:

git clone https://github.com/Valbef/DeautDetectorESP32.git



Instalación en Linux:

sudo apt update

sudo apt install python3 python3-pip python3-venv

cd deauth-detector

python3 -m venv .venv

source .venv/bin/activate

pip install --upgrade pip

pip install scapy pyserial


---------------------------------------------------------


 En el ESP32

Necesitas:

    ESP32-WROOM-32 (no lo he probado con otros)

    Cable USB de datos.

    Arduino IDE.

    Librería/soporte de placas ESP32 de Espressif.

En Arduino IDE:

    Instala Arduino IDE.

    Abre Preferences / Preferencias.

    Añade el paquete de placas ESP32 de Espressif en el gestor de placas.

    Abre Boards Manager / Gestor de placas.

    Instala esp32 by Espressif Systems.

    Selecciona tu placa, por ejemplo:

        ESP32-WROOM-32, ESP32 Dev Module

    Selecciona el puerto serie correspondiente.

    Carga el archivo FirmwareESP32DeauthDetector.ino
    o copia el contenido de FirmwareESP32DeauthDetector.txt

El ESP32 debe quedar conectado por USB al ordenador Linux.



Conecta el ESP32 y mira qué puerto aparece:

ls /dev/ttyUSB*

o:

ls /dev/ttyACM*

Por ejemplo:

/dev/ttyUSB0


Normalmente el usuario debe pertenecer al grupo dialout:

sudo usermod -aG dialout $USER


Después cierra sesión y vuelve a entrar para que el cambio tenga efecto.
---------------------------------------------------------

Uso:

cd DeauthDetectorESP32

source .venv/bin/activate

python3 DeauthDetector.py
