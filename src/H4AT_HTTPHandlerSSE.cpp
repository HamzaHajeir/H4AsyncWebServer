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

H4AT_HTTPHandlerSSE::H4AT_HTTPHandlerSSE(const std::string& url, size_t backlog): _bs(backlog),H4AT_HTTPHandler(HTTP_GET,url) { 
    H4AS_PRINT1("SSE HANDLER CTOR %p backlog=%d\n",this,_bs);
    reset();
}

H4AT_HTTPHandlerSSE::~H4AT_HTTPHandlerSSE(){ H4AS_PRINT1("SSE HANDLER DTOR %p\n",this); }

bool H4AT_HTTPHandlerSSE::_execute(){
    _clients.insert(_r);
    auto c=_r;
    c->onDisconnect([=](){
        _clients.erase(c);
        if(!_clients.size()) {
            h4.cancelSingleton(H4AS_SSE_KA_ID); // needed ?
            reset();
            _cbConnect(0); // notify all gone
        }
    });
//    dumpClients();
    auto lid=atoi(_sniffHeader["last-event-id"].data());
    if(lid){
        H4AS_PRINT3("It's a reconnect! lid=%d\n",lid);
        for(auto b:_backlog){
            if(b.first > lid) c->TX((const uint8_t *) b.second.data(),b.second.size());
        }
    } else H4AS_PRINT1("New SSE Client %p\n",c);
    _headers["Cache-Control"]="no-cache";
    H4AT_HTTPHandler::send(200,"text/event-stream",0,nullptr); // explicitly send zero!
    h4.queueFunction([=]{ 
        H4AS_PRINT1("SSE CLIENT %p\n",c);
        std::string retry("retry: ");
        retry.append(stringFromInt(H4AS_SCAVENGE_FREQ)).append("\n\n");
        c->TX((const uint8_t *) retry.data(),retry.size());
        _cbConnect(_clients.size());
    });
    h4.every((H4AS_SCAVENGE_FREQ * 2) / 3,[=]{ send(":"); },nullptr,H4AS_SSE_KA_ID,true); // name it
    return true;
}

void H4AT_HTTPHandlerSSE::reset() { 
    H4AS_PRINT1("%p H4AT_HTTPHandlerSSE::reset 1\n",this);
    H4AT_HTTPHandler::reset();
    _backlog.clear();
    _nextID=0;
    _sniffHeader["last-event-id"]=""; // AND CTOR?
}

void H4AT_HTTPHandlerSSE::saveBacklog(const std::string& m){
    _backlog[_nextID]=m;
    if(_backlog.size() > _bs) _backlog.erase(_nextID - _bs);
}

void H4AT_HTTPHandlerSSE::send(const std::string& message, const std::string& event){
    char buf[16];
    std::string rv;
    if(message[0]==':') rv=message+"\n";
    else {
        rv.append("id: ").append(itoa(++_nextID,buf,10)).append("\n");
        if(event.size()) rv+="event: "+event+"\n";
        std::vector<std::string> data;
        char *token = strtok(const_cast<char*>(message.data()), "\n");
        while (token != nullptr){
            data.push_back(std::string(token));
            token = strtok(nullptr, "\n");
        }
        for(auto &d:data) rv+="data: "+d+"\n";
    }
    rv+="\n";
    for(auto &c:_clients) c->TX((const uint8_t *) rv.data(),rv.size());
    if(_bs) saveBacklog(rv);
}