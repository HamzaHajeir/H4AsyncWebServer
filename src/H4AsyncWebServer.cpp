/*
MIT License

Copyright (c) 2026 H4Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Contact Email: TBD
*/
#include<H4AsyncWebServer.h>

void H4AsyncWebServer::addHandler(H4AW_HTTPHandler* h){ 
    h->_init(this); 
    _handlers.push_back(h);
}

void H4AsyncWebServer::begin(){
    H4AW_PRINT1("SERVER BEGIN %p\n",this);
    onError([=](int e,int i){ 
        H4AT_PRINT1("H4AsyncWebServer ERROR %d %d\n",e,i);
        return true;
    });
    addHandler(new H4AW_HTTPHandlerFile(_FSPath, _auth));
    addHandler(new H4AW_HTTPHandler404);
    H4AsyncServer::begin();
}

void H4AsyncWebServer::on(const char* path,int verb,H4AW_RQ_HANDLER f,bool authenticate){ addHandler(new H4AW_HTTPHandler{verb,path,authenticate,f}); }

void H4AsyncWebServer::reset(){
    H4AsyncServer::reset();
    H4AW_PRINT1("H4AsyncWebServer::reset()\n");
    for(auto &h:_handlers){
        H4AW_PRINT2("reset handler %s %s\n",h->_verbName().data(),h->_path.data());
        h->_reset();
        delete h;
    }
    _handlers.clear();
    H4AW_PRINT1("H4AsyncWebServer::reset() handlers cleared\n");
}

void H4AsyncWebServer::route(void* c,const uint8_t* data,size_t len){
    auto r=reinterpret_cast<H4AW_HTTPRequest*>(c);

    std::vector<std::string> rqst=split(std::string((const char*)data,len),"\r\n");
    H4AW_PRINT1("%p ROUTE %s data=%p len=%d\n",r,rqst[0].data(),data,len);
    if (rqst[0].find("HTTP/1.1") == std::string::npos || split(rqst[0], " ").size() < 3) { // bad input, might filter further
        H4AW_PRINT1("Corrupted request rqst[0]=%s\n", rqst[0].c_str());
        return;
    }
    std::vector<std::string> sub=split(replaceAll(rqst[0],"HTTP/1.1",""),"?");
    if(sub.size() > 1) r->_paramsFromstring(sub[1]);
    std::vector<std::string> vparts=split(sub[0]," ");

    H4T_NVP_MAP _rqHeaders;
    for(auto &req:std::vector<std::string>(++rqst.begin(),--rqst.end())){
        std::vector<std::string> rparts=split(req,":");
        if(rparts.size() > 1)
        {
            auto trimmed=trim(rparts[1]);
            _rqHeaders[uppercase(rparts[0])] = urldecode(trimmed);
            r->_addHeader(rparts[0], trimmed);
        }
    }
        
//    for(auto &r:_rqHeaders) Serial.printf("RQ %s=%s\n",r.first.data(),r.second.data());

    r->_blen=atoi(r->_getHeader(_rqHeaders,txtContentLength()).data());
    if(r->_blen){ // refactor get
        r->_body=static_cast<uint8_t*>(malloc(r->_blen));
        memcpy(r->_body,data+len-r->_blen,r->_blen);
//        Serial.printf("SAVING BODY RQ=%p b=%p l=%d\n",r,r->_body,r->_blen);
        if(r->_getHeader(_rqHeaders,"Content-type")=="application/x-www-form-urlencoded") r->_paramsFromstring(std::string ((const char*) r->_body,r->_blen));
        else H4AW_PRINT1("received weird type %s\n",r->_getHeader(_rqHeaders,"Content-type").data());
    }
    //
    H4AW_PRINT1("Handling %p %s %s\n", r, vparts[0].data(), vparts[1].data());
    for(auto h:_handlers){
        for(auto &s:h->_sniffHeader) if(_rqHeaders.count(uppercase(s.first))) h->_sniffHeader[s.first]=_rqHeaders[uppercase(s.first)];
        if(h->_select(r,vparts[0],vparts[1])) break;
    }
}