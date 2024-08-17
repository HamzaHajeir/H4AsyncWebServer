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
#include <H4AsyncWebServer.h>

H4_INT_MAP http_verb_names = { // tidy
    {HTTP_ANY,"*"},
    {HTTP_GET,"GET"},
    {HTTP_HEAD,"HEAD"},
    {HTTP_POST,"POST"},
    {HTTP_PUT,"PUT"},
    {HTTP_DELETE,"DELETE"},
    {HTTP_CONNECT,"CONNECT"},
    {HTTP_OPTIONS,"OPTIONS"},
    {HTTP_TRACE,"TRACE"},
    {HTTP_PATCH,"PATCH"}
};

H4_INT_MAP H4AW_HTTPHandler::_responseCodes{ // lose this?
    {100,"Continue"},
    {101,"Switching Protocols"},
    {200,"OK"},
    {303,"See Other"},
    {304,"Not Modified"},
    {400,"Bad Request"},
    {401,"Unauthorized"},
    {403,"Forbidden"},
    {404,"Not Found"},
    {408,"Request Time-out"},
    {413,"Payload Too Large"}, 
    {415,"Unsupported Media Type"},
    {429,"Too many requests"},
    {500,"Internal Server Error"},
    {503,"Service Unavailable"}
};

H4T_NVP_MAP H4AW_HTTPHandler::mimeTypes={
  {"html","text/html"},
  {"htm","text/html"},
  {"css","text/css"},
  {"json","application/json"},
  {"js","application/javascript"},
  {"png","image/png"},
  {"jpg","image/jpeg"},
  {"ico","image/x-icon"},
  {"xml","text/xml"},
};
//
//  H4AW_HTTPRequest
//
std::string H4AW_HTTPRequest::_getHeader(H4T_NVP_MAP& m,const char* h){
    std::string uh=uppercase(h);
    return m.count(uh) ? m[uh]:"";
}

void H4AW_HTTPRequest::_paramsFromstring(const std::string& bod){
    std::vector<std::string> prams=split(bod,"&");
    for(auto &p:prams){
        std::vector<std::string> nvp=split(p,"=");
        std::string value=nvp.size()==2 ? nvp[1]:"";
        params[nvp[0]]=urldecode(value);
    }
}
//
// H4AW_HTTPHandler
//
bool H4AW_HTTPHandler::_execute(){
    if(_f) _f(this);
    return true;
}

bool H4AW_HTTPHandler::_match(const std::string& verb,const std::string& path){
    if(verb==_verbName()){
        if(_path.size() > 1) return path.find(_path,0)==0;
        else return _path==path;
    } else return false;
}

bool H4AW_HTTPHandler::_notFound(){
    send(404,mimeType("txt"),5,"oops!");
    return true;
}

bool H4AW_HTTPHandler::_select(H4AW_HTTPRequest* r,const std::string& verb,const std::string& path){
    _r=r;
    _r->url=urldecode(path);
    H4AW_PRINT2("Handler select rq=%p url=%s  v=%s[%s] p=%s[%s]\n",_r,_r->url.data(),_verbName().data(),verb.data(),_path.data(),path.data());
    if(_match(verb,path)){
        bool ok = true;
        if (_authenticate && _srv->_auth) {
            ok = _srv->_auth->authenticate(this);
            H4AW_PRINT1("Authentication %s\n", ok?"Succeeded" : "Failed");
        }
        if (ok) {
            bool rv=_execute();
            _reset();
            return rv;
        }
        return true; // IS Handled by the authenticator.
    } else return false;
}

bool H4AW_HTTPHandler::_serveFile(const char* fn){
    H4AW_PRINT2("Serve file %s\n",fn);
    bool rv=false;
    char crlf[]={'0','\r','\n','\r','\n'};
    size_t force_fit=TCP_MSS - 7 - _r->getTLSOverhead(); // allow chunk embellishment not to overflow "sensible" buf size hex\r\n ... \r\n == 7
    h4t::readFileChunks(fn,force_fit,
        [&](const uint8_t* data,size_t len){
            std::string hex=stringFromInt(len,"%03x\r\n");
            size_t total=len+hex.size()+2;
            uint8_t* buff=static_cast<uint8_t*>(malloc(total));
            memcpy(buff,hex.data(),hex.size());
            memcpy(buff+hex.size(),data,len);
            memcpy(buff+hex.size()+len,&crlf[3],2);
            _r->TX(buff,total);
            free(buff);
        },
        [&](size_t size){
            if(size){
                _headers["Transfer-Encoding"]="chunked";
                _headers["Cache-Control"]="max-age="+stringFromInt(_srv->_cacheAge);
                send(200,mimeType(fn),0,nullptr);
            }/*  else _notFound();//send(404,"text/plain",5,"oops!"); */ // 404Handler sends it.
        },
        [&]{
            H4AW_PRINT1("ALL CHUNKED OUT for %s\n",_path.data());
            _r->TX((const uint8_t*) crlf,5);
            rv=true;
        }
    );
    return rv;
}

std::string H4AW_HTTPHandler::_verbName(){ return http_verb_names[_verb]; }

std::string H4AW_HTTPHandler::mimeType(const char* f){
    std::string fn(f);
    std::string e = fn.substr(fn.rfind('.')+1);
    return mimeTypes.count(e) ? mimeTypes[e]:"text/plain";
}

void H4AW_HTTPHandler::redirect(const char* location){
    H4AW_PRINT1("H4AW_HTTPHandler::redirect -> %s\n",location);
    addHeader("Location",location);
    send(303,mimeType("txt"),0,nullptr); // tidy this (et al) : no mimetype when length == 0!
}

void H4AW_HTTPHandler::_reset(){
    H4AW_PRINT1("H4AW_HTTPHandler::reset() 1 %p _r=%p\n",this,_r);
    _headers.clear();
}

void H4AW_HTTPHandler::send(uint16_t code,const std::string& type,size_t length,const void* _body){
    H4AW_PRINT2("H4AW_HTTPHandler %p send(%d,%s,%d,%p)\n",this,code,type.data(),length,_body);
    std::string status=std::string("HTTP/1.1 ")+stringFromInt(code,"%3d ").append(_responseCodes[code])+"\r\n";
    _headers["Content-Type"]=type;
    if(length) _headers[txtContentLength()]=stringFromInt(length);
    for(auto const& h:_headers) status+=h.first+": "+h.second+"\r\n";
    status+="\r\n";
    //
    auto h=status.size();
    auto total=h+length;
    uint8_t* buff=(uint8_t*) malloc(total);
    if(buff){
        memcpy(buff,status.data(),h);
        if(length) memcpy(buff+h,_body,length);
        if (_r->connected())
            _r->TX(buff,total);
        free(buff);
    } 
    else H4AW_PRINTF("AAAAAAAAARGH H4AW_HTTPHandler::send zero buff\n");
}
/*
void H4AW_HTTPHandler::sendFileParams(const char* fn,H4T_FN_LOOKUP f){
    sendstring(mimeType(fn), replaceParams(h4t::readFile(fn),f));
}
*/
void H4AW_HTTPHandler::sendFileParams(const char* fn,H4T_NVP_MAP& nvp){
    sendstring(mimeType(fn), replaceParams(h4t::readFile(fn),nvp));
}
//
// H4AW_HTTPHandlerFile match only verb, treat path as static filename
//
bool H4AW_HTTPHandlerFile::_match(const std::string& verb,const std::string& path) {
    _path=path;
    return verb==_verbName();
}