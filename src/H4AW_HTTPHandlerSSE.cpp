/*
MIT License

Copyright (c) 2026 H4Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Contact Email: TBD
*/
#include<H4AsyncWebServer.h>

H4AW_HTTPHandlerSSE::H4AW_HTTPHandlerSSE(const std::string& url, size_t backlog, bool auth): H4AW_HTTPHandler(HTTP_GET,url,auth),_bs(backlog) { 
    H4AW_PRINT1("SSE HANDLER CTOR %p backlog=%d\n",this,_bs);
    _reset();
}

H4AW_HTTPHandlerSSE::~H4AW_HTTPHandlerSSE(){ H4AW_PRINT1("SSE HANDLER DTOR %p\n",this); }

bool H4AW_HTTPHandlerSSE::_execute(){
    _clients.insert(_r);
    auto c=_r;
    c->onDisconnect([=, this](){
        _clients.erase(c);
        if(!_clients.size()) {
            h4.cancelSingleton(H4AS_SSE_KA_ID); // needed ?
            _reset();
            _cbConnect(0); // notify all gone
        }
    });
//    dumpClients();
    _headers["Cache-Control"]="no-cache";
    H4AW_HTTPHandler::send(200,"text/event-stream",0,nullptr); // explicitly send zero!
    auto lid=atoi(_sniffHeader["last-event-id"].data());
    h4.queueFunction([=, this]{ 
        H4AW_PRINT1("SSE CLIENT %p\n",c);
        std::string retry("retry: ");
        retry.append(stringFromInt(H4AS_SCAVENGE_FREQ)).append("\n\n");
        auto tcpConnected = c->connected();
        if (tcpConnected)
            c->TX((const uint8_t *) retry.data(),retry.size());
        _cbConnect(_clients.size());
        if(lid){
            H4AW_PRINT3("It's a reconnect! lid=%d send backlog of %d\n",lid,_backlog.size());
            for(auto b:_backlog) if(b.first > lid) if (tcpConnected) c->TX((const uint8_t *) b.second.data(),b.second.size());
        } else H4AW_PRINT1("New SSE Client %p\n",c);
    });
    h4.every((H4AS_SCAVENGE_FREQ * 2) / 3,[this]{ send(":"); },nullptr,H4AS_SSE_KA_ID,true); // name it
    return true;
}

void H4AW_HTTPHandlerSSE::_reset() { 
    H4AW_PRINT1("%p H4AW_HTTPHandlerSSE::reset 1\n",this);
    H4AW_HTTPHandler::_reset();
    _backlog.clear();
    _nextID=0;
    _sniffHeader["last-event-id"]=""; // AND CTOR?
}

void H4AW_HTTPHandlerSSE::send(const std::string& message, const std::string& event){
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
    for(auto &c:_clients) if (c->connected()) c->TX((const uint8_t *) rv.data(),rv.size());
    if(_bs) {
        _backlog[_nextID]=rv;
        if(_backlog.size() > _bs) _backlog.erase(_nextID - _bs);
    }
}