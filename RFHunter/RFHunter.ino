/* =====================
   This software is licensed under the MIT License:
   https://github.com/spacehuhntech/esp8266_deauther
   ===================== */

extern "C" {
    // Please follow this tutorial:
    // https://github.com/spacehuhn/esp8266_deauther/wiki/Installation#compiling-using-arduino-ide
    // And be sure to have the right board selected
  #include "user_interface.h"
}

#include <SPI.h>
#include <RF24.h>

#include "EEPROMHelper.h"

#include "src/ArduinoJson-v5.13.5/ArduinoJson.h"
#if ARDUINOJSON_VERSION_MAJOR != 5
// The software was build using ArduinoJson v5.x
// version 6 is still in beta at the time of writing
// go to tools -> manage libraries, search for ArduinoJSON and install version 5
#error Please upgrade/downgrade ArduinoJSON library to version 5!
#endif // if ARDUINOJSON_VERSION_MAJOR != 5

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

//#include "led.h"  dont in use 

#define PIN_CE  16
#define PIN_CSN 15

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
    DEAUTHER_SUITE
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
    "Deauther-Suite"
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
void returnToMainMenu();
void updateMainMenu();
void updateNrfMenu();
void updateNrfRunning();
void updateDeautherSuite();

void setup() {
    // for random generator
    randomSeed(os_random());

    // start serial
    Serial.begin(115200);
    Serial.println();

    // start SPIFFS
    prnt(SETUP_MOUNT_SPIFFS);
    // bool spiffsError = !LittleFS.begin();
    LittleFS.begin();
    prntln(/*spiffsError ? SETUP_ERROR : */ SETUP_OK);

    // Start EEPROM
    EEPROMHelper::begin(EEPROM_SIZE);

#ifdef FORMAT_SPIFFS
    prnt(SETUP_FORMAT_SPIFFS);
    LittleFS.format();
    prntln(SETUP_OK);
#endif // ifdef FORMAT_SPIFFS

#ifdef FORMAT_EEPROM
    prnt(SETUP_FORMAT_EEPROM);
    EEPROMHelper::format(EEPROM_SIZE);
    prntln(SETUP_OK);
#endif // ifdef FORMAT_EEPROM

    // Format SPIFFS when in boot-loop
    if (/*spiffsError || */ !EEPROMHelper::checkBootNum(BOOT_COUNTER_ADDR)) {
        prnt(SETUP_FORMAT_SPIFFS);
        LittleFS.format();
        prntln(SETUP_OK);

        prnt(SETUP_FORMAT_EEPROM);
        EEPROMHelper::format(EEPROM_SIZE);
        prntln(SETUP_OK);

        EEPROMHelper::resetBootNum(BOOT_COUNTER_ADDR);
    }

    // get time
    currentTime = millis();

    // load settings
    #ifndef RESET_SETTINGS
    settings::load();
    #else // ifndef RESET_SETTINGS
    settings::reset();
    settings::save();
    #endif // ifndef RESET_SETTINGS

    // start display
    if (settings::getDisplaySettings().enabled) {
        displayUI.setup();
        displayUI.mode = DISPLAY_MODE::OFF;
        drawMainMenu();
    }

    // STARTED
    prntln(SETUP_STARTED);

    // version
    prntln(DEAUTHER_VERSION);

    // setup LED
    //led::setup();

}

void loop() {
    currentTime = millis();

    switch (appMode) {
        case AppMode::MAIN_MENU:
            updateMainMenu();
            break;

        case AppMode::NRF_MENU:
            updateNrfMenu();
            break;

        case AppMode::NRF_RUNNING:
            updateNrfRunning();
            break;

        case AppMode::DEAUTHER_SUITE:
            updateDeautherSuite();
            break;
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
        } else {
            startDeautherSuite();
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
    // led::update();   // update LED color
    wifi::update();  // manage access point
    attack.update(); // run attacks
    displayUI.update();
    cli.update();    // read and run serial input
    scan.update();   // run scan
    ssids.update();  // run random mode, if enabled

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
