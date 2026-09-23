#include <WiFi.h>
#include <esp_wifi.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"


// =========================================================
// CONFIGURACIÓN
// =========================================================

#define SERIAL_BAUD 921600

#define MAX_FRAME_SIZE 1600

#define QUEUE_SIZE 16

#define MAGIC_1 0xAA
#define MAGIC_2 0x55


// =========================================================
// ESTRUCTURA
// =========================================================

struct CapturedFrame {

    uint8_t channel;

    uint16_t length;

    uint32_t timestamp;

    int8_t rssi;

    uint8_t data[MAX_FRAME_SIZE];
};


// =========================================================
// QUEUE
// =========================================================

QueueHandle_t frameQueue;


// =========================================================
// ESTADO
// =========================================================

volatile uint8_t currentChannel = 1;


// Contadores internos de diagnóstico.

volatile uint32_t framesReceived = 0;
volatile uint32_t framesDropped = 0;
volatile uint32_t framesTooLarge = 0;


// =========================================================
// CALLBACK PROMISCUO
// =========================================================

void wifi_promiscuous_callback(
    void *buffer,
    wifi_promiscuous_pkt_type_t type
) {

    if (buffer == nullptr) {
        return;
    }

    // -----------------------------------------------------
    // Solo 802.11
    // -----------------------------------------------------

    if (
        type != WIFI_PKT_MGMT &&
        type != WIFI_PKT_DATA &&
        type != WIFI_PKT_CTRL
    ) {

        return;
    }

    wifi_promiscuous_pkt_t *packet =
        (wifi_promiscuous_pkt_t *)buffer;

    uint16_t length =
        packet->rx_ctrl.sig_len;

    if (length == 0) {
        return;
    }

    framesReceived++;

    // -----------------------------------------------------
    // No truncar silenciosamente
    // -----------------------------------------------------

    if (
        length > MAX_FRAME_SIZE
    ) {

        framesTooLarge++;

        return;
    }

    // -----------------------------------------------------
    // Crear frame
    // -----------------------------------------------------

    CapturedFrame frame;

    frame.channel =
        currentChannel;

    frame.length =
        length;

    frame.timestamp =
        millis();

    frame.rssi =
        packet->rx_ctrl.rssi;

    memcpy(
        frame.data,
        packet->payload,
        length
    );

    // -----------------------------------------------------
    // Queue
    // -----------------------------------------------------

    if (
        xQueueSend(
            frameQueue,
            &frame,
            0
        ) != pdTRUE
    ) {

        framesDropped++;
    }
}


// =========================================================
// CAMBIO DE CANAL
// =========================================================

bool setChannel(
    uint8_t channel
) {

    if (
        channel < 1 ||
        channel > 14
    ) {

        return false;
    }

    esp_err_t result =
        esp_wifi_set_channel(
            channel,
            WIFI_SECOND_CHAN_NONE
        );

    if (
        result != ESP_OK
    ) {

        return false;
    }

    currentChannel =
        channel;

    return true;
}


// =========================================================
// ENVIAR FRAME
// =========================================================

void sendFrame(
    const CapturedFrame &frame
) {

    // -----------------------------------------------------
    // HEADER
    //
    // AA 55
    // channel      1 byte
    // length       2 bytes
    // timestamp    4 bytes
    // rssi         1 byte
    //
    // TOTAL = 10 bytes
    // -----------------------------------------------------

    uint8_t header[10];

    header[0] =
        MAGIC_1;

    header[1] =
        MAGIC_2;

    header[2] =
        frame.channel;

    header[3] =
        frame.length & 0xFF;

    header[4] =
        (frame.length >> 8) & 0xFF;

    header[5] =
        frame.timestamp & 0xFF;

    header[6] =
        (frame.timestamp >> 8) & 0xFF;

    header[7] =
        (frame.timestamp >> 16) & 0xFF;

    header[8] =
        (frame.timestamp >> 24) & 0xFF;

    // RSSI como int8.
    header[9] =
        (uint8_t)frame.rssi;

    Serial.write(
        header,
        sizeof(header)
    );

    Serial.write(
        frame.data,
        frame.length
    );
}


// =========================================================
// COMANDOS SERIE
// =========================================================

void processSerialCommand() {

    static String command = "";

    while (
        Serial.available()
    ) {

        char c =
            Serial.read();

        if (
            c == '\n' ||
            c == '\r'
        ) {

            if (
                command.length() == 0
            ) {

                continue;
            }

            // ---------------------------------------------
            // C<number>
            // ---------------------------------------------

            if (
                command[0] == 'C' ||
                command[0] == 'c'
            ) {

                int channel =
                    command
                        .substring(1)
                        .toInt();

                if (
                    channel >= 1 &&
                    channel <= 14
                ) {

                    setChannel(
                        channel
                    );
                }
            }

            command = "";

        } else {

            command += c;

            if (
                command.length() > 16
            ) {

                command = "";
            }
        }
    }
}


// =========================================================
// SETUP
// =========================================================

void setup() {

    // -----------------------------------------------------
    // SERIAL
    // -----------------------------------------------------

    Serial.begin(
        SERIAL_BAUD
    );

    delay(1000);

    // -----------------------------------------------------
    // WIFI
    // -----------------------------------------------------

    WiFi.mode(
        WIFI_MODE_NULL
    );

    delay(100);

    esp_wifi_set_promiscuous(
        false
    );

    // -----------------------------------------------------
    // QUEUE
    // -----------------------------------------------------

    frameQueue =
        xQueueCreate(
            QUEUE_SIZE,
            sizeof(CapturedFrame)
        );

    if (
        frameQueue == nullptr
    ) {

        while (true) {

            delay(1000);
        }
    }

    // -----------------------------------------------------
    // CANAL INICIAL
    // -----------------------------------------------------

    if (
        !setChannel(1)
    ) {

        while (true) {

            delay(1000);
        }
    }

    // -----------------------------------------------------
    // CALLBACK
    // -----------------------------------------------------

    esp_wifi_set_promiscuous_rx_cb(
        &wifi_promiscuous_callback
    );

    // -----------------------------------------------------
    // FILTRO
    // -----------------------------------------------------

    wifi_promiscuous_filter_t filter;

    filter.filter_mask =
        WIFI_PROMIS_FILTER_MASK_ALL;

    esp_wifi_set_promiscuous_filter(
        &filter
    );

    // -----------------------------------------------------
    // PROMISCUOUS
    // -----------------------------------------------------

    esp_wifi_set_promiscuous(
        true
    );

    delay(100);
}


// =========================================================
// LOOP
// =========================================================

void loop() {

    // -----------------------------------------------------
    // COMANDOS DEL PC
    // -----------------------------------------------------

    processSerialCommand();

    // -----------------------------------------------------
    // OBTENER FRAME
    // -----------------------------------------------------

    CapturedFrame frame;

    if (
        xQueueReceive(
            frameQueue,
            &frame,
            pdMS_TO_TICKS(10)
        ) == pdTRUE
    ) {

        sendFrame(
            frame
        );
    }
}
