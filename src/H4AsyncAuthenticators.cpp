#pragma once

#include "H4AsyncWebServer.h"
#include "libb64/cdecode.h"

constexpr const char* txtAuthorization() { return "Authorization"; }
constexpr const char* txtAuthentication() { return "WWW-Authenticate"; }
constexpr const char* txtSetCookie() { return "Set-Cookie"; }
constexpr const char* txtCookie() { return "cookie"; }


constexpr const char* txtBasic() { return "Basic"; }
constexpr const char* txtDigest() { return "Digest"; }
constexpr const char* txtSessionID() { return "session_id"; }

bool H4AW_BasicAuthenticator::authenticate(H4AW_HTTPHandler *handler)
{
	H4AW_PRINT1("Authenticating user [%s] psk [%s]\n", username.c_str(), password.c_str());
	auto& reqHeaders = handler->req_headers();
	if (reqHeaders.count(txtAuthorization())) {
		std::string authValue = reqHeaders[txtAuthorization()];
		auto parts = split(authValue, " ");
		if (parts.size() != 2 || parts[0].compare(txtBasic()) != 0) { 
			H4AW_PRINT1("Bad authValue %s\n", authValue.c_str());
			return requestAuthentication(handler), false;
		}


		auto encoded = parts[1];
		char dec[base64_decode_expected_len(encoded.length())];
		base64_decodestate s;
		/* initialise the decoder state */
		base64_init_decodestate(&s);
		auto rv = base64_decode_block(encoded.c_str(), encoded.length(), dec, &s);
		if (rv) {
			std::string decoded{dec};
			auto decParts = split(decoded,":");
			if (decParts.size() == 2 && decParts[0] == username && decParts[1] == password) {
				// Generate Sesssion ID.
				// Add Session ID to the map alongwith timeout.

				// handler->addHeader(txtSetCookie(), "");
				H4AW_PRINT1("Accepted!\n");
				return true;
			}
		} else 
			H4AW_PRINT1("b64 fail decode!\n");
		requestAuthentication(handler);
		return false;
	}
	/* else if (reqHeaders.count(txtCookie()))
	{
		// Fetch session_id
		// validate against stored session id
		// if expired, requestAuthentication + return false;
		// else extend time + return true; (10 minutes from now)
	} */
	else
	{
		H4AW_PRINT1("No Authorization Header!\n");
		requestAuthentication(handler);
		return false;
	}
}

void H4AW_BasicAuthenticator::requestAuthentication(H4AW_HTTPHandler *handler)
{

/*   response.headers().add("WWW-Authenticate", "Basic realm=\"My Application\"");
  response.result(http::status::unauthorized);
 */
	std::string resp{txtBasic()};
	resp.append(" realm=\"").append(realm).append("\"");
	handler->addHeader(txtAuthentication(), resp);
	handler->addHeader("Connection", "close");
	handler->send(401,handler->mimeType("txt"));
	handler->_r->close();
}
