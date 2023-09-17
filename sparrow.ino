#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL (500)
#define WIFI_CHANNEL_MAX (13)

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc = "CN", .schan = 1, .nchan = 13}; // Most recent esp32 library struct

#define MAX_HIST_LEN 16
#define MIN_MOVEMENT_THRESHOLD 3

typedef struct
{
    uint8_t mac[6];
    int8_t hist_rssi[MAX_HIST_LEN];
    uint32_t last_seen;
    uint32_t first_seen;
    uint8_t hist_index;
} mac_instance;

// list of all seen MAC addresses
#define MAX_MACS 1024
mac_instance macs[MAX_MACS];
uint8_t macs_index = 0;
uint8_t macs_count = 0;

typedef struct
{
    unsigned frame_ctrl : 16;
    unsigned duration_id : 16;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* filtering address */
    unsigned sequence_ctrl : 16;
    uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct
{
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
    return ESP_OK;
}

void wifi_sniffer_init(void)
{
    nvs_flash_init();
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel)
{
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
    switch (type)
    {
    case WIFI_PKT_MGMT:
        return "MGMT";
    case WIFI_PKT_DATA:
        return "DATA";
    default:
    case WIFI_PKT_MISC:
        return "MISC";
    }
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // check if mac address is already in list
    for (int i = 0; i < macs_count; i++)
    {
        if (memcmp(macs[i].mac, hdr->addr2, 6) == 0)
        {
            // check if rssi is different from last seen
            if (abs(macs[i].hist_rssi[(macs[i].hist_index - 1) % MAX_HIST_LEN] - (int8_t) ppkt->rx_ctrl.rssi) < MIN_MOVEMENT_THRESHOLD)
            {
                return;
            }
            // Update history
            macs[i].hist_rssi[macs[i].hist_index] = ppkt->rx_ctrl.rssi;
            macs[i].first_seen = ppkt->rx_ctrl.timestamp;
            macs[i].last_seen = ppkt->rx_ctrl.timestamp;
            macs[i].hist_index = (macs[i].hist_index + 1) % MAX_HIST_LEN;
            return;
        }
    }

    // add mac address to list
    memcpy(macs[macs_index].mac, hdr->addr2, 6);
    macs[macs_index].hist_rssi[0] = ppkt->rx_ctrl.rssi;
    macs[macs_index].last_seen = ppkt->rx_ctrl.timestamp;
    macs[macs_index].hist_index = 1;
    macs_index = (macs_index + 1) % MAX_MACS;
    if (macs_count < MAX_MACS)
        macs_count++;
}

// the setup function runs once when you press reset or power the board
void setup()
{
    // initialize digital pin 5 as an output.
    Serial.begin(115200);
    delay(10);
    wifi_sniffer_init();
}

void print_mac(uint8_t *mac)
{
    Serial.printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// the loop function runs over and over again forever
void loop()
{
    // Serial.print("inside loop");
    delay(1000); // wait for a second

    // Print all seen MAC addresses with more than 1 RSSI value
    Serial.println("\n\n---------------------------------------------------------------");
    for (int i = 0; i < macs_count; i++)
    {
        if (macs[i].hist_index == 1)
            continue;
        print_mac(macs[i].mac);
        Serial.printf("\n");
        for (int j = MAX_HIST_LEN - 1; j >= 0; j--)
        {
            uint8_t hist_index = (j + (macs[i].hist_index)) % MAX_HIST_LEN;
            if (macs[i].hist_rssi[hist_index] == 0)
                break;
            Serial.printf(" - %02d\n", macs[i].hist_rssi[hist_index]);
        }
        Serial.printf("\n");
        // Serial.printf("%02x:%02x:%02x:%02x:%02x:%02x - %d\n", macs[i][0], macs[i][1], macs[i][2], macs[i][3], macs[i][4], macs[i][5], timestamps[i]);
    }

    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    wifi_sniffer_set_channel(channel);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;
}
