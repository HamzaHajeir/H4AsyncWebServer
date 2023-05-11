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

#define LIB "H4AsyncTCP"
#define DEVICE "FORM_HANDLER"
  
#include<H4AsyncWebServer.h>

H4AsyncWebServer s(80);

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

  s.on("/",HTTP_GET,[](H4AW_HTTPHandler* h){
    h->sendFile("/sta.htm");
  });   
  
  s.on("/form",HTTP_POST,[](H4AW_HTTPHandler* h){
    Serial.printf("FORM from %s URL=%s\n",h->client()->remoteIPstring().data(),h->url().data());
    for(auto const& p:h->params()) Serial.printf("Param %s=%s\n",p.first.data(),p.second.data());
    Serial.printf("BODY DATA\n");
    dumphex(h->bodyData(),h->bodySize());
    std::string cmd=h->params()["cmd"];
    Serial.printf("Individual parameter cmd=%s\n",cmd.data());
    if(cmd=="h4plugins") h->redirect("https://github.com/philbowles/h4plugins");
    else h->redirect("/");
  });   

  s.begin();
}