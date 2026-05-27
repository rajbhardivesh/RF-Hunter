# RF Hunter — Wireless Security Research Platform

**ESP8266 + nRF24L01 · OLED Display · Open Source Hardware & Firmware**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: ESP8266](https://img.shields.io/badge/Platform-ESP8266-orange.svg)]()
[![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

> A compact, standalone wireless security research device. Three tools in one — RF jammer, Wi-Fi deauther, and captive portal testbed — controlled from a 128×64 OLED display and 6-button keypad. No laptop required.

---

## Buy a pre-built unit

If you want to skip the build and get straight to learning:

**[→ Buy RF-Hunter at rdhrobotics.in](https://rdhrobotics.in/products/rf-hunter)**

Assembled, tested, and shipped. Includes quick-start card.

---

## What it does

The RF-Hunter is a hardware platform for studying 2.4 GHz wireless security concepts hands-on. It runs three independent research modules from a unified launcher UI:

| Module | Description |
|---|---|
| **RF-Hunter** | Sweeps all 125 nRF24 channels or Wi-Fi bands only. Studies RF interference in the 2.4 GHz space. |
| **Deauther Suite** | spacehuhn deauther engine. Scan APs, study 802.11 management frame behaviour. |
| **WiPhi** | Evil twin AP + captive portal testbed. Study how credential phishing portals work. |
| **RF Chat** | *(bonus sketch)* Point-to-point text chat over raw nRF24 radio. |

Everything is navigated from the OLED + keypad, or remotely via the built-in web admin panel at `192.168.4.1`.

---

## Hardware

| Component | Part |
|---|---|
| MCU | ESP8266 (80/160 MHz, 2.4 GHz Wi-Fi) |
| RF module | nRF24L01+ PA+LNA |
| Display | SH1106 128×64 OLED (I²C) |
| Input | 6-button ADC keypad (voltage divider) |
| Storage | EEPROM — 5-slot credential vault, persists across reboots |

### Pinout

```raw
nRF24L01   CE  → GPIO16
           CSN → GPIO15

SH1106     SDA → GPIO4
           SCL → GPIO5
```

### ADC button thresholds

```cpp
#define BTN_UP     135
#define BTN_DOWN   579
#define BTN_LEFT   426
#define BTN_RIGHT  634
#define BTN_ENTER  729
#define BTN_BACK   687
```

Adjust values to match your resistor network.

---

## Firmware

### Requirements

- Arduino IDE 1.8+ or PlatformIO
- ESP8266 board package
- Libraries: `RF24`, `ESP8266WiFi`, `DNSServer`, `ESP8266WebServer`, `SH1106Wire` (ESP8266-OLED), `ADCButton`, `ArduinoJson v5`

### Install

```bash
git clone https://github.com/rdhrobotics/RF-Hunter.git
```

Open `RFHunter/RFHunter.ino` in Arduino IDE. Select **Generic ESP8266 (Deauther)** as the board. Flash at 115200 baud.

### Repository structure

```raw
RF-Hunter/
├── RFHunter/
│   └── RFHunter.ino        ← main sketch (all three tools)
│
├── Hardware Source/
│   ├── RD_Deauther.pdf // schematic
│   └── RD_Deauther.kicad_pro // Kicad Project

```

---

## UI overview

```raw
┌─────────────────┐
│     Main Menu   │  ← Launcher
│  > RF-Hunter    │
│    Deauther     │
│    WiPhi        │
└─────────────────┘
        │
        ├── RF-Hunter → select mode → running (BACK to stop)
        ├── Deauther  → full spacehuhn DisplayUI
        └── WiPhi     → scan → select AP → attack → captured PW
```

Hold **BACK for 5 seconds** from any mode to return to the launcher main menu.

---

## Adding a new RF mode (3 steps)

The launcher uses a mode table — drop in a new attack without touching the state machine.

**Step 1** — declare your functions:
```cpp
void myMode_init();
void myMode_tick();
```

**Step 2** — add a row to the table:
```cpp
const NrfMode NRF_MODES[] = {
    { "BLE & All 2.4GHz", nrfAttackAllInit,  nrfAttackAllTick,  true },
    { "Just Wi-Fi",       nrfAttackWiFiInit, nrfAttackWiFiTick, true },
    { "My New Mode",      myMode_init,       myMode_tick,       false }, // ← add here
};
```

**Step 3** — write the functions anywhere below. Done.

---

## EEPROM layout

WiPhi saves captured credentials to EEPROM and survives power cycles.

```raw
Addr 0        Magic byte (0xAB) — detects first boot
Addr 1–485    5 slots × (1 valid flag + 32 SSID + 64 PW)

WiPhi vault (in Launcher, offset to avoid deauther collision):
Addr 2000     Magic byte (0xBC)
Addr 2001+    Same slot layout × 5
```

Browse and delete saved passwords from the OLED: **Main Menu → Saved Passwords**.

---

## Web admin panel

While WiPhi is running, connect to:

```raw
SSID:     WiPhi_34732
Password: d347h320
URL:      http://192.168.4.1/admin
```

The web UI and OLED run simultaneously — control from either.

---

## Open source

This project is fully open source — firmware and hardware both.

| | License |
|---|---|
| Firmware | [MIT](LICENSE) |
| Hardware (schematic, BOM) | [CERN OHL v2 Permissive](LICENSE-HW) |

The Deauther Suite module uses the [spacehuhn/esp8266_deauther](https://github.com/SpacehuhnTech/esp8266_deauther) engine, which is also MIT licensed.

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Ethical use

This device is built for **authorized security research, CTF competitions, and educational use**.

- Only use on networks and devices you own or have explicit written permission to test
- Unauthorized deauthentication, RF jamming, or credential harvesting is illegal in most jurisdictions
- The authors take no responsibility for misuse

---

## Made with ❤️

by [@rdhrobotics](https://rdhrobotics.in) — open hardware for security education.

**[→ Buy pre-built at rdhrobotics.in](https://rdhrobotics.in/products/rf-hunter)**
