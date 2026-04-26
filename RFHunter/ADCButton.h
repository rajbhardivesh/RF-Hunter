#pragma once

#include <Arduino.h>
#include <functional>

typedef std::function<void()> ButtonEventFunction;

class ADCButton {
    public:
        ADCButton(uint16_t targetValue, uint16_t tolerance = 30);
        ~ADCButton();

        void update();
        
        void setOnClicked(ButtonEventFunction fnct);
        void setOnClicked(ButtonEventFunction fnct, uint32_t minPushTime);
        void setOnClicked(ButtonEventFunction fnct, uint32_t minPushTime, uint32_t minReleaseTime);
        
        void setOnHolding(ButtonEventFunction fnct, uint32_t holdTime = 500);
        
        bool clicked();
        bool pushed();
        bool released();
        bool holding(uint32_t time);
        
        int read();

    private:
        uint16_t targetValue;
        uint16_t tolerance;
        uint16_t currentADCValue = 0;
        
        bool buttonState = false;
        bool previousState = false;
        
        bool clickedFlag = false;
        bool pushedFlag = false;
        bool releasedFlag = false;
        bool holdingFlag = false;
        
        uint32_t pressTime = 0;
        uint32_t releaseTime = 0;
        uint32_t updateTime = 0;
        
        uint32_t minPushTime = 40;
        uint32_t minReleaseTime = 40;
        uint32_t holdTime = 500;
        uint32_t updateInterval = 10;
        
        ButtonEventFunction onClickedCallback = nullptr;
        ButtonEventFunction onHoldingCallback = nullptr;
        
        bool isPressed();
        void checkStateChange();
};
