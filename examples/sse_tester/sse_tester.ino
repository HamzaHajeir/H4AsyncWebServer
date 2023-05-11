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
H4 h4(115200);

#define DEVICE "SSE_TESTER"
  
#include<H4AsyncWebServer.h>
H4AsyncWebServer s(80);
H4AW_HTTPHandlerSSE* _evts=nullptr;
#define LIB "H4AsyncTCP"
H4AT_NVP_MAP lookup={
    {"device",DEVICE}
};

#define UI_UPDATER 42

void h4setup(){
  Serial.printf("MIMIC H4P to get FS started on pesky ESP!\n");
  HAL_FS.begin(); // ESP32 cannot call this from constructor, so... mimic H4Plugins :)  

  WiFi.mode(WIFI_STA);
  WiFi.begin("XXXXXXXX", "XXXXXXXX");
  while (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("Connection Failed! Rebooting...");
    delay(5000);
    ESP.restart();
  }
  Serial.printf("\nIP: %s\n",WiFi.localIP().toString().c_str());

  Serial.printf("Cry 'Havoc!' and let receive the packets of War!\n\n");

  _evts=new H4AW_HTTPHandlerSSE("/evt");//,10); // backlog = 10
  _evts->onChange([=](size_t nClients){
      Serial.printf("_evts->onChange N=%d\n",nClients);
      if(nClients){
        // do setup stuff, start timers etc
        h4.every(500,[=]{
          static bool led=false;
          _evts->send(stringFromInt(millis()).data(),"millis");
          _evts->send(stringFromInt(_HAL_freeHeap()).data(),"heap");
          _evts->send(stringFromInt(_HAL_maxHeapBlock()).data(),"maxblock");
          _evts->send(stringFromInt(led).data(),"LED");led=!led;
        },nullptr,UI_UPDATER,true);
        // send UI seup stuff
        // statics
        _evts->send("library,0,s,0,0," LIB,"ui");
        _evts->send("device,0,s,0,0," DEVICE,"ui");
        _evts->send((std::string("chip,0,s,0,0,")+_HAL_uniqueName("ESP_")).data(),"ui");
        _evts->send("board,0,s,0,0," MY_BOARD,"ui");
        _evts->send("Son1,0,s,0,0,Huey","ui");
        _evts->send("Son2,0,s,0,0,Louie","ui");
        _evts->send("Son3,0,s,0,0,Dewey","ui");
        // dynamics
        _evts->send("millis,0,s,0,0,0","ui");
        _evts->send("heap,0,s,0,0,0","ui");
        _evts->send("maxblock,0,s,0,0,0","ui");                 
        _evts->send("LED,1,g,0,5,0","ui");   
      }
      else { // client == 0 means all clients gone away
        Serial.printf("No more clients, stop some stuff!\n");
        h4.cancelSingleton(UI_UPDATER);
      }
  });

  s.on("/",HTTP_GET,[](H4AW_HTTPHandler* h){
    h->sendFileParams("/sta.htm",lookup); // refac
  });   

  s.addHandler(_evts);
  s.begin();
}