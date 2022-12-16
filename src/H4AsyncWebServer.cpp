/*
Creative Commons: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

You are free to:

Share — copy and redistribute the material in any medium or format
Adapt — remix, transform, and build upon the material

The licensor cannot revoke these freedoms as long as you follow the license terms. Under the following terms:

Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. 
You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

NonCommercial — You may not use the material for commercial purposes.

ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions 
under the same license as the original.

No additional restrictions — You may not apply legal terms or technological measures that legally restrict others 
from doing anything the license permits.

Notices:
You do not have to comply with the license for elements of the material in the public domain or where your use is 
permitted by an applicable exception or limitation. To discuss an exception, contact the author:

philbowles2012@gmail.com

No warranties are given. The license may not give you all of the permissions necessary for your intended use. 
For example, other rights such as publicity, privacy, or moral rights may limit how you use the material.
*/
#include<H4AsyncWebServer.h>

void H4AsyncWebServer::addHandler(H4AW_HTTPHandler* h){ 
    h->_init(this); 
    _handlers.push_back(h);
}

void H4AsyncWebServer::begin(){
    H4AW_PRINT1("SERVER BEGIN %p\n",this);
    onError([=](int e,int i){ 
        if(e!=ERR_CLSD) Serial.printf("H4AsyncWebServer ERROR %d %d\n",e,i);
        return true;
    });
    H4AsyncClient::_scavenge();
    addHandler(new H4AW_HTTPHandlerFile);
    addHandler(new H4AW_HTTPHandler404);
    H4AsyncServer::begin();
}

void H4AsyncWebServer::on(const char* path,int verb,H4AW_RQ_HANDLER f){ addHandler(new H4AW_HTTPHandler{verb,path,f}); }

void H4AsyncWebServer::reset(){
    H4AW_PRINT1("H4AsyncWebServer::reset()\n");
    for(auto &h:_handlers){
        H4AW_PRINT1("reset handler %s %s\n",h->_verbName().data(),h->_path.data());
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
        else Serial.printf("received weird type %s\n",r->_getHeader(_rqHeaders,"Content-type").data());
    }
    //
    for(auto h:_handlers){
        for(auto &s:h->_sniffHeader) if(_rqHeaders.count(uppercase(s.first))) h->_sniffHeader[s.first]=_rqHeaders[uppercase(s.first)];
        if(h->_select(r,vparts[0],vparts[1])) break;
    }
}