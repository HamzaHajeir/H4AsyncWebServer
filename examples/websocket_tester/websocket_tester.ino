#ifdef ARDUINO_ARCH_ESP8266
  #include<ESP8266WiFi.h>
  #define MY_BOARD "Wemos D1 Mini"
#else
  #include<WiFi.h>
  #define MY_BOARD "ESP32 Dev Board"
#endif
#include<LittleFS.h>
#define HAL_FS LittleFS


#include <H4.h>
#include<H4AsyncWebServer.h>
H4 h4(115200);

#define TICK  1000
#define DEVICE "WEBSOCKET_TEST"

H4_TIMER  ticker;

H4AsyncWebServer s(80);
H4AW_HTTPHandlerWS* _ws=nullptr;
#define LIB "H4AsyncTCP"

void h4setup(){
  HAL_FS.begin(); // ESP32 cannot call this from constructor, so... mimic H4Plugins :)  
  WiFi.mode(WIFI_STA);
  WiFi.begin("XXXXXXXX", "XXXXXXXX");
  while (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("Connection Failed! Rebooting...");
    delay(5000);
    ESP.restart();
  }
  Serial.printf("\nIP: %s\n",WiFi.localIP().toString().c_str());

  _ws=new H4AW_HTTPHandlerWS("/ws");
  _ws->onOpen([](H4AW_WebsocketClient* skt){
    h4.queueFunction([skt,_ws]{ 
      skt->sendText("lib,%s/%s",LIB,H4AT_VERSION);
      skt->sendText("board,%s",MY_BOARD);
      skt->sendText("default,You are No. %d",_ws->size());
    });
    ticker=h4.every(TICK,[=]{
      _ws->broadcastText("millis,%u",millis());
      _ws->broadcastText("heap,%u",_HAL_freeHeap());
      _ws->broadcastText("mhb,%u",_HAL_maxHeapBlock());
      _ws->broadcastText("rnd1,%u",random(0,1000));
      _ws->broadcastText("rnd2,%u",random(0,2000));
      _ws->broadcastText("rnd3,%u",random(0,3000));
      _ws->broadcastText("n,%d",_ws->size());
    });
  });
  
  _ws->onTextMessage([](H4AW_WebsocketClient* skt,const std::string& msg){
    skt->sendText(msg+" sent by user");
  });
  
  _ws->onClose([](H4AW_WebsocketClient* skt){ if(!_ws->size()) h4.cancel(ticker); });
  s.on("/",HTTP_GET,[](H4AW_HTTPHandler* h){ h->sendFile("/index.htm"); });   
  s.addHandler(_ws);  
  s.begin();
}