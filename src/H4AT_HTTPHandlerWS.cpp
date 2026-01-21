/*
MIT License

Copyright (c) 2026 H4Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Contact Email: TBD
*/
#include <H4AsyncWebServer.h>
#include <base64.h>
#include <Arduino.h>

#if defined(ARDUINO_ARCH_ESP8266) || defined(ARDUINO_ARCH_RP2040)
    #include <Hash.h>
    std::string _HAL_wsEncode(const std::string& k){
        uint8_t bentos[20];
        sha1(k.data(),k.size(),bentos);
        return std::string(base64::encode(bentos,20,false).c_str());
    }
#else
    #include "sha/sha_parallel_engine.h"
    std::string _HAL_wsEncode(const std::string& k){ 
        uint8_t bentos[20];
        esp_sha(esp_sha_type::SHA1, (const uint8_t*) k.data(),k.size(), bentos);
        return std::string(base64::encode(bentos,20).c_str());
    }
#endif
//
//      H4AW_WebsocketClient
//
void H4AW_WebsocketClient::_sendFrame(uint8_t opcode,const uint8_t* data,uint16_t len){
    size_t ls=len > 125 ? 3:1;
    size_t fs=1+ls+len;
    auto frame=static_cast<uint8_t*>(malloc(fs));
    auto p=frame;
    *p++=0x80 | opcode;
    *p++=(ls > 1) ? 126:len;
    if(ls > 1){
        *p++=(len & 0xff00) >> 8;
        *p++=(len & 0xff);
    }
    memcpy(p,data,len);
    if (connected())
        TX(frame,fs);
    free(frame);
}
//
//      H4AW_HTTPHandlerWS
//
H4AW_HTTPHandlerWS::H4AW_HTTPHandlerWS(const std::string& url, bool auth): H4AW_HTTPHandler(HTTP_GET,url,auth) { _reset(); }

H4AW_HTTPHandlerWS::~H4AW_HTTPHandlerWS(){ H4AW_PRINT1("WS HANDLER DTOR %p\n",this); }

bool H4AW_HTTPHandlerWS::_execute(){
    H4AW_PRINT1("EXECUTE %p\n",_r);
    auto c=reinterpret_cast<H4AW_WebsocketClient*>(_r);
    _clients.insert(c);
    if(_cbOpen) _cbOpen(c);
    c->onDisconnect([c,this](){
        _clients.erase(c);
        if(_cbClose) _cbClose(c);
        if(!_clients.size()) {
            h4.cancelSingleton(H4AS_WS_KA_ID); // needed ?
            _reset();
        }
    });
    c->onRX([c, this](const uint8_t* data,size_t len){ _socketMessage(c,data,len); });
    auto k=_sniffHeader[txtSecWebsocketKey()].append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    _headers["Sec-WebSocket-Accept"]=_HAL_wsEncode(k);
    _headers["Upgrade"]="websocket";
    _headers["Connection"]="Upgrade";
    H4AW_HTTPHandler::send(101,mimeType("txt")); // mimetype this
    h4.every((H4AS_SCAVENGE_FREQ * 2) / 3,[c, this]{ for(auto const& c:_clients) c->_sendFrame(WS_PING); },nullptr,H4AS_WS_KA_ID,true);
    return true;
}

void H4AW_HTTPHandlerWS::_socketMessage(H4AW_WebsocketClient* r,const uint8_t* data,uint16_t len){
    uint8_t opcode=data[0] & 0x0f;
    uint16_t size=data[1] & 0x7f;
    auto offset=const_cast<uint8_t*>(&data[2]);
    uint8_t  mask[4];
    if(data[1] & 0x80){
        if(size==126){
            size=((*offset) << 8) | *(offset+1);
            offset+=2;
        }
        for(int i=0;i<4;i++) mask[i]=*(offset++);
        for(int i = 0; i < size; i++) offset[i] ^= mask[i % 4];
        switch(opcode){
            case WS_TEXT:
                if(_cbTxt) _cbTxt(r,std::string((const char*) offset,size));
				break;
            case WS_BINARY:
                if(_cbBin) _cbBin(r,offset,size);
				break;
            case WS_CLOSE:
                r->_shutdown();
				break;
            default:
				break;
        }
    }
}
//
void H4AW_HTTPHandlerWS::broadcastBinary(const uint8_t* data,size_t len){ for(auto const& c:_clients) c->sendBinary(data,len); }

void H4AW_HTTPHandlerWS::_reset() { _sniffHeader[txtSecWebsocketKey()]=""; }