#include "ADCButton.h"

ADCButton::ADCButton(uint16_t targetValue, uint16_t tolerance) 
    : targetValue(targetValue), tolerance(tolerance) {
    updateTime = millis();
}

ADCButton::~ADCButton() {}

int ADCButton::read() {
    currentADCValue = analogRead(A0);  // ESP8266 has only one ADC pin at A0
    return currentADCValue;
}

bool ADCButton::isPressed() {
    uint16_t adcValue = read();
    // Check if ADC value is within tolerance range of target value
    return (adcValue >= targetValue - tolerance) && (adcValue <= targetValue + tolerance);
}

void ADCButton::update() {
    uint32_t now = millis();
    
    // Only update at specified interval
    if (now - updateTime < updateInterval) {
        return;
    }
    
    updateTime = now;
    previousState = buttonState;
    buttonState = isPressed();
    
    checkStateChange();
}

void ADCButton::checkStateChange() {
    uint32_t now = millis();
    
    // Button pressed (state changed from false to true)
    if (buttonState && !previousState) {
        pressTime = now;
        pushedFlag = true;
        clickedFlag = false;
        releasedFlag = false;
        holdingFlag = false;
    }
    
    // Button released (state changed from true to false)
    if (!buttonState && previousState) {
        releaseTime = now;
        releasedFlag = true;
        
        // Check if it was a click (pressed and released within min times)
        uint32_t pressDuration = releaseTime - pressTime;
        if (pressDuration >= minPushTime && (now - pressTime) >= minPushTime) {
            clickedFlag = true;
            if (onClickedCallback) {
                onClickedCallback();
            }
        }
    }
    
    // Check for holding
    if (buttonState) {
        uint32_t holdDuration = now - pressTime;
        if (holdDuration >= holdTime && !holdingFlag) {
            holdingFlag = true;
            if (onHoldingCallback) {
                onHoldingCallback();
            }
        }
    }
}

void ADCButton::setOnClicked(ButtonEventFunction fnct) {
    setOnClicked(fnct, minPushTime, minReleaseTime);
}

void ADCButton::setOnClicked(ButtonEventFunction fnct, uint32_t minPushTime) {
    setOnClicked(fnct, minPushTime, minReleaseTime);
}

void ADCButton::setOnClicked(ButtonEventFunction fnct, uint32_t minPushTime, uint32_t minReleaseTime) {
    this->minPushTime = minPushTime;
    this->minReleaseTime = minReleaseTime;
    onClickedCallback = fnct;
}

void ADCButton::setOnHolding(ButtonEventFunction fnct, uint32_t holdTime) {
    this->holdTime = holdTime;
    onHoldingCallback = fnct;
}

bool ADCButton::clicked() {
    if (clickedFlag) {
        clickedFlag = false;
        return true;
    }
    return false;
}

bool ADCButton::pushed() {
    if (pushedFlag) {
        pushedFlag = false;
        return true;
    }
    return false;
}

bool ADCButton::released() {
    if (releasedFlag) {
        releasedFlag = false;
        return true;
    }
    return false;
}

bool ADCButton::holding(uint32_t time) {
    return (buttonState && (millis() - pressTime >= time));
}
