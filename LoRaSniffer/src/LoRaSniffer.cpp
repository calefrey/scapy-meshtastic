/**
 * Captures LoRa Packets and dumps them to a serial terminal
 * Modified to specifically capture meshtastic packets for later processing
 *
 * For use with the CatWAN USB Stick
 * https://github.com/ElectronicCats/CatWAN_USB_Stick
 * For Flashing instructions see wiki:
 * https://github.com/ElectronicCats/CatWAN_USB_Stick/wiki/4.-First-Steps-with-CatWAN-USB-Stick
 */

#include <Arduino.h>
#include <LoRa.h>
#include <loratap.h>

// Will need to change based on location and preset. See:
// https://meshtastic.org/docs/overview/radio-settings/ and
// https://meshtastic.org/docs/overview/mesh-algo/
// Frequency for default channel in USA
// Settings for Long_Fast USA:

#define FREQ 906.875E6 // channel frequency
#define BW 250E3       // bandwidth
#define SF 11          // spread factor
#define CR 5           // coding rate denominator. Numerator is 4
#define SW 0x2B        // syncword, 2b for meshtastic

// device-specific pinouts to connect to radio
#define SS 17
#define RFM_RST 21
#define RFM_DIO0 10
#define RFM_DIO5 15

#define LT_LEN 15 // count up the bytes

void setup()
{
  Serial.begin(9600);
  while (!Serial)
  {
    ;
  }

  LoRa.setPins(SS, RFM_RST, RFM_DIO0);
  if (!LoRa.begin(FREQ))
  {
    Serial.println("Starting LoRa failed!");
    while (1)
      ;
  }
  LoRa.setSyncWord(SW);
  LoRa.setPreambleLength(16);

  LoRa.setSpreadingFactor(SF);
  LoRa.setCodingRate4(CR);
  LoRa.setSignalBandwidth(BW);
}

void loop()
{
  // try to parse packet
  int packetSize = LoRa.parsePacket();
  if (packetSize)
  {
    // populate LoRaTap header
    loratap_header_t header;
    header.lt_version = 0;
    header.lt_padding = 0;
    // Values should be big-endian, so multi-byte values need to be reordered
    header.lt_length = __bswap16(LT_LEN);
    header.channel.frequency = __bswap32(FREQ);
    header.channel.bandwidth = BW / 125E3; // bandwidth in 125k steps
    header.channel.sf = SF;
    header.rssi.packet_rssi = LoRa.packetRssi();
    header.rssi.max_rssi = 0xFF; // unsure, leaving undefined
    header.rssi.current_rssi = LoRa.rssi();
    header.rssi.snr = LoRa.packetSnr();
    header.sync_word = SW;

    // write header data
    Serial.write((byte *)&header, LT_LEN);

    // read and send packet data
    while (LoRa.available())
    {
      Serial.write((byte)LoRa.read());
    }
    // mark EOF
    Serial.write(0xCF);
    Serial.write(0xCF);
  }
}