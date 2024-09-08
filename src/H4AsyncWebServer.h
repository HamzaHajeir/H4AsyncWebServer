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
#pragma once

#include<H4AsyncTCP.h>
#include"h4asws_config.h"

#define _H4AW_PRINTF(...) _H4T_PRINTF(__VA_ARGS__)
#if H4AW_DEBUG
    #define H4AW_PRINTF(...) _H4AW_PRINTF(__VA_ARGS__)
    template<int I, typename... Args>
    void H4AW_PRINT(const char* fmt, Args... args) {
        #ifdef ARDUINO_ARCH_ESP32
        if (H4AW_DEBUG >= I) H4AW_PRINTF(std::string(std::string("H4AS:%d: H=%u M=%u S=%u ")+fmt).c_str(),I,_HAL_freeHeap(),_HAL_maxHeapBlock(),uxTaskGetStackHighWaterMark(NULL),args...);
        #else
        if (H4AW_DEBUG >= I) H4AW_PRINTF(std::string(std::string("H4AS:%d: H=%u M=%u ")+fmt).c_str(),I,_HAL_freeHeap(),_HAL_maxHeapBlock(),args...);
        #endif
    }
    #define H4AW_PRINT1(...) H4AW_PRINT<1>(__VA_ARGS__)
    #define H4AW_PRINT2(...) H4AW_PRINT<2>(__VA_ARGS__)
    #define H4AW_PRINT3(...) H4AW_PRINT<3>(__VA_ARGS__)
    #define H4AW_PRINT4(...) H4AW_PRINT<4>(__VA_ARGS__)

    template<int I>
    void H4AW_DUMP(const uint8_t* p, size_t len) { if (H4AW_DEBUG >= I) dumphex(p,len); }
    #define H4AW_DUMP1(p,l) H4AW_DUMP<1>((p),l)
    #define H4AW_DUMP2(p,l) H4AW_DUMP<2>((p),l)
    #define H4AW_DUMP3(p,l) H4AW_DUMP<3>((p),l)
    #define H4AW_DUMP4(p,l) H4AW_DUMP<4>((p),l)
#else
    #define H4AW_PRINTF(...)
    #define H4AW_PRINT1(...)
    #define H4AW_PRINT2(...)
    #define H4AW_PRINT3(...)
    #define H4AW_PRINT4(...)

    #define H4AW_DUMP2(...)
    #define H4AW_DUMP3(...)
    #define H4AW_DUMP4(...)
#endif

enum {
    HTTP_ANY,
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_CONNECT,
    HTTP_OPTIONS,
    HTTP_TRACE,
    HTTP_PATCH
};

enum {
    WS_TEXT=1,
    WS_BINARY,
    WS_CLOSE=8,
    WS_PING
};

class H4AsyncWebServer;
class H4AW_HTTPRequest: public H4AsyncClient {
    public:
                uint8_t*        _body=nullptr;
                size_t          _blen=0;
                H4T_NVP_MAP     params;
                std::string     url;
                H4T_NVP_MAP     headers;

        H4AW_HTTPRequest(altcp_pcb* p): H4AsyncClient(p){ H4AW_PRINT1("H4AW_HTTPRequest CTOR %p\n",this);}
        virtual ~H4AW_HTTPRequest(){ 
            H4AW_PRINT1("H4AW_HTTPRequest DTOR %p body=%p\n",this,_body);
            if(_body){
                H4AW_PRINT1("H4AW_HTTPRequest DTOR %p body=%p\n",this,_body);
                free(_body);
            }
        }
// don't call
        static  std::string     _getHeader(H4T_NVP_MAP& m,const char* h);
                void            _paramsFromstring(const std::string& bod);
                void            _addHeader(const std::string &h, const std::string &v) { headers[h] = v; }
};

class H4AW_WebsocketClient: public H4AW_HTTPRequest {
    public:
        H4AW_WebsocketClient(altcp_pcb* p): H4AW_HTTPRequest(p){}
        virtual ~H4AW_WebsocketClient(){}

                void            sendBinary(const uint8_t* data,size_t len){ _sendFrame(WS_BINARY,data,len); }
                template<typename... Args>
                void            sendText(const char*,Args&&...);
                void            sendText(const std::string& s){ _sendFrame(WS_TEXT,(const uint8_t*) s.data(),s.size()); }
// don't call
                void            _sendFrame(uint8_t opcode,const uint8_t* data=nullptr,uint16_t len=0);
};

template<typename... Args>
void H4AW_WebsocketClient::sendText(const char* fmt, Args&&... args){ // variadic T<>
    char* buff=static_cast<char*>(malloc(256+1));
    snprintf(buff,256,fmt,args...);
    _sendFrame(WS_TEXT,(const uint8_t*) buff,strlen(buff));
    free(buff);
}
//
//  H4AW_Authenticator + derivatives
//
class H4AW_HTTPHandler;
class H4AW_Authenticator {
    virtual void requestAuthentication(H4AW_HTTPHandler*) = 0;
protected:
    std::string username;
    std::string password;
    std::string realm;
    H4AW_Authenticator(const std::string& username, const std::string& password, const std::string& realm="h4asyncws") : username(username), password(password), realm(realm) {}
    virtual ~H4AW_Authenticator() = default;
    H4AW_Authenticator(const H4AW_Authenticator& other) = default;
    H4AW_Authenticator& operator=(const H4AW_Authenticator& other) = default;
    H4AW_Authenticator(H4AW_Authenticator&& other) = default;
    H4AW_Authenticator& operator=(H4AW_Authenticator&& other) = default;

public:
    virtual bool authenticate(H4AW_HTTPHandler*) = 0;
    virtual void changeAuth(const std::string& username, const std::string& password) {
        this->username = username;
        this->password = password;
    }
};

class H4AW_BasicAuthenticator : public H4AW_Authenticator 
{
    void requestAuthentication(H4AW_HTTPHandler* handler) override;
public:
    H4AW_BasicAuthenticator(const std::string& username, const std::string& password, const std::string& realm="h4asyncws") : H4AW_Authenticator(username,password,realm) {}
    bool authenticate(H4AW_HTTPHandler* handler) override;
};
//
//   H4AW_HTTPHandler + derivatives
//
using H4AW_RQ_HANDLER    =std::function<void(H4AW_HTTPHandler*)>;

class H4AW_HTTPHandler {
    protected:
                H4AW_RQ_HANDLER     _f=nullptr;
        static  H4_INT_MAP          _responseCodes;

        virtual bool                _execute();
        virtual bool                _match(const std::string& verb,const std::string& path);

    public:
                int                 _verb;
                std::string         _path;
                H4T_NVP_MAP         _headers; // hoist!
                H4AW_HTTPRequest*   _r=nullptr;
                H4T_NVP_MAP         _sniffHeader; // thinl: tidy??
                H4AsyncWebServer*   _srv;
                bool                _authenticate=true;

        static  H4T_NVP_MAP         mimeTypes;

        H4AW_HTTPHandler(int verb,const std::string& path,bool authenticate=true,H4AW_RQ_HANDLER f=nullptr): _f(f),_verb(verb),_path(path),_authenticate(authenticate){
            H4AW_PRINT1("H4AW_HTTPHandler CTOR %p v=%d vn=%s p=%s\n",this,_verb,_verbName().data(),path.data());
        }
        virtual ~H4AW_HTTPHandler(){ 
            H4AW_PRINT1("H4AW_HTTPHandler DTOR %p\n",this);
            _reset(); // prob don't need this
        }
                void                addHeader(const std::string& name,const std::string& value){ _headers[name]=value; }
                uint8_t*            bodyData(){ return _r->_body; }
                size_t              bodySize(){ return _r->_blen; } // tidy these
                H4AW_HTTPRequest*   client(){ return _r; }
        static  std::string         mimeType(const char* fn);
                H4T_NVP_MAP&        params(){ return _r->params; }
                H4T_NVP_MAP&        req_headers(){ return _r->headers; }
                void                redirect(const char* fn);
        virtual void                send(uint16_t code,const std::string& type,size_t length=0,const void* body=nullptr);
        virtual void                sendFile(const char* fn){ _serveFile(fn); }
        virtual void                sendFileParams(const char* fn,H4T_NVP_MAP& nvp);
                void                sendOK(){ send(200,mimeType("txt"),0,nullptr); }
        virtual void                sendstring(const std::string& type,const std::string& data){ send(200,type,data.size(),(const void*) data.data()); }
                std::string         url(){ return _r->url; } // tidy these
//      don't call
                bool                _notFound();
        virtual void                _init(H4AsyncWebServer* srv){ _srv=srv; }
        virtual void                _reset();
                bool                _select(H4AW_HTTPRequest* r,const std::string& verb,const std::string& path);
        virtual bool                _serveFile(const char* fn);
                std::string         _verbName();
};

class H4AW_HTTPHandlerFile: public H4AW_HTTPHandler {
                std::string _servePath;
    protected:
        virtual bool    _execute() override { return _serveFile(_path.data()); }
        virtual bool    _match(const std::string& verb,const std::string& path) override;
        virtual bool    _serveFile(const char* fn) { std::string full_path = _servePath + fn;
                                                        return H4AW_HTTPHandler::_serveFile(full_path.c_str());}
    public:
        /* servePath should start with forward slash "/" */
        H4AW_HTTPHandlerFile(const std::string& servePath = "", bool authenticate=true): H4AW_HTTPHandler(HTTP_GET, "*", authenticate), _servePath(servePath){};
//      don't call
        virtual void    _reset() override { _path="*"; } // not REALLY needed
};

class H4AW_HTTPHandler404: public H4AW_HTTPHandler {
    protected:
        virtual bool    _execute() override { return _notFound(); }
        virtual bool    _match(const std::string& verb,const std::string& path) override { return true; }
    public:
        H4AW_HTTPHandler404(): H4AW_HTTPHandler(HTTP_ANY,"404"){}
};

using H4AW_EVT_HANDLER   = std::function<void(size_t)>;
using H4AW_SSE_LIST      = std::unordered_set<H4AsyncClient*>;

class H4AW_HTTPHandlerSSE: public H4AW_HTTPHandler {
            H4AW_SSE_LIST                       _clients;
            H4AW_EVT_HANDLER                    _cbConnect;
            std::map<size_t,std::string>        _backlog;
            size_t                              _bs;
            size_t                              _nextID=0;
    protected:
        virtual bool                _execute() override;
    public:
        H4AW_HTTPHandlerSSE(const std::string& url,size_t backlog=0,bool authenticate=true);
        ~H4AW_HTTPHandlerSSE();

                void                onChange(H4AW_EVT_HANDLER cb){ _cbConnect=cb; }
                void                send(const std::string& message, const std::string& event="");
                size_t              size(){ return _clients.size(); }
//      don't call
        virtual void                _reset() override;
};

using H4AW_WS_LIST       = std::unordered_set<H4AW_WebsocketClient*>;
using H4AW_FN_WSEVENT    = std::function<void(H4AW_WebsocketClient*)>;
using H4AW_FN_WSTXT      = std::function<void(H4AW_WebsocketClient*,const std::string&)>;
using H4AW_FN_WSBIN      = std::function<void(H4AW_WebsocketClient*,const uint8_t*,size_t)>;

class H4AW_HTTPHandlerWS: public H4AW_HTTPHandler {
                H4AW_WS_LIST        _clients;
                H4AW_FN_WSEVENT     _cbOpen=nullptr;
                H4AW_FN_WSEVENT     _cbClose=nullptr;
                H4AW_FN_WSBIN       _cbBin=nullptr;
                H4AW_FN_WSTXT       _cbTxt=nullptr;

                void                 _socketMessage(H4AW_WebsocketClient* r,const uint8_t* data,uint16_t len);
    protected:
        virtual bool                 _execute() override;
    public:

        H4AW_HTTPHandlerWS(const std::string& url, bool authenticate=true);
        ~H4AW_HTTPHandlerWS();

                void                broadcastBinary(const uint8_t* data,size_t len);
                template<typename... Args>
                void                broadcastText(const char* fmt, Args... args){ for(auto const& c:_clients) c->sendText(fmt, args...); }
                void                broadcastText(const std::string& msg){ for(auto const& c:_clients) c->sendText(msg); }
                void                onBinaryMessage(H4AW_FN_WSBIN cb){ _cbBin=cb; }
                void                onClose(H4AW_FN_WSEVENT cb){ _cbClose=cb; }
                void                onOpen(H4AW_FN_WSEVENT cb){ _cbOpen=cb; }
                void                onTextMessage(H4AW_FN_WSTXT cb){ _cbTxt=cb; }
                size_t              size(){ return _clients.size(); }
//
                void                dumpClients(){ for(auto const& c:_clients) _H4AW_PRINTF("   WS CLIENT %p\n",c); }
// just dont...
        virtual void                _reset() override;
};

using H4AW_HANDLER_LIST  = std::vector<H4AW_HTTPHandler*>;

class H4AsyncWebServer: public H4AsyncServer {
        static  void                _scavenge();
                std::string         _FSPath;
    public:
            H4AW_Authenticator*     _auth=nullptr;
            size_t                  _cacheAge;
            H4AW_HANDLER_LIST       _handlers;

        H4AsyncWebServer(uint16_t port,size_t cacheAge=H4AW_CACHE_AGE): H4AsyncServer(port), _cacheAge(cacheAge){}
        virtual ~H4AsyncWebServer(){}

                void            setFSPath(const std::string & FSPath) { _FSPath = FSPath; }; /* Should start with forward slash "/" */
                void            addHandler(H4AW_HTTPHandler* h);
                void            begin() override;
                void            setAuthenticator(H4AW_Authenticator* auth) { _auth = auth; }
                void            setPort(uint16_t port) { _port = port; }
                void            on(const char* path,int verb,H4AW_RQ_HANDLER f,bool authenticate=true);

        virtual void            reset();
// don't call
                H4AsyncClient*  _instantiateRequest(struct altcp_pcb* p) override { return reinterpret_cast<H4AsyncClient*>(new H4AW_HTTPRequest(p)); }
                void            route(void* c,const uint8_t* data,size_t len) override;
};

constexpr const char* txtContentLength(){ return "Content-Length"; }
constexpr const char* txtSecWebsocketKey(){ return "Sec-Websocket-Key"; }