/*
MIT License

Copyright (c) 2026 H4Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Contact Email: TBD
*/
#include <H4AsyncWebServer.h>

std::vector<std::string> wisdom={
    "Don't eat yellow snow",
    "A dead Yak never flies at night",
    "Click to subscribe to the <a href=\"https://www.youtube.com/channel/UCYi-Ko76_3p9hBUtleZRY6g\">YouTube channel!</a>",
    "The roses are pink in Moscow today",
    "47 muscles to frown, only 12 to pull the trigger on a sniper rifle",
    "You have the luxury of not knowing what I know",
    "Support me on Patreon! <div class=\"lnk\"><a href=\"https://patreon.com/esparto\" rel=\"noopener\" target=\"_blank\"><img src=\"/patreon.jpg\"></image></a></div></div>",
    "Never put off till tomorrow what will keep till the day after",
    "There is no problem so big you can't walk away from it",
    "Money cannot buy happiness, but its more comfortable to cry in a Mercedes than on a bicycle",
    "Forgive your enemy, but remember the bastard's name",
    "Help someone when they are in trouble, and they will remember you when they are in trouble again",
    "It is better to stay silent and be thought a fool, than to open one's mouth and immediately remove all doubt",
    "Many people are alive today only because it's illegal to shoot them",
    "Alcohol does not solve any problems, but neither does milk"
};

class RandomQuoteServer: public H4AsyncWebServer {
  public:
    RandomQuoteServer(uint16_t port): H4AsyncWebServer(port){
        on("/",HTTP_GET,[=](H4AW_HTTPHandler* h){
            std::string html="<HTML><BODY><CENTER><H1>"+wisdom[random(0,wisdom.size())]+"</H1></CENTER></BODY></HTML>";
            h->sendstring(H4AW_HTTPHandler::mimeTypes["htm"],html);
        });
    }
};