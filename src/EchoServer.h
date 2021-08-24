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

class EchoServer;

class EchoRequest: public H4AS_Request<EchoServer> {
    public:
        EchoRequest(tcp_pcb* p,EchoServer* server): H4AS_Request<EchoServer>(p,server){}
        
        void        process(const uint8_t* data,size_t len) override { TX(data,len); }
};

class EchoServer: public H4AsyncServer {
  public:
    EchoServer(uint16_t port): H4AsyncServer(port){}

    void _incoming(tcp_pcb* p) override { newConnection(p,new EchoRequest(p,this)); }
};