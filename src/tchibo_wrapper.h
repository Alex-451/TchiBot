#ifndef TCHIBO_WRAPPER_H
#define TCHIBO_WRAPPER_H

#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>

using namespace std;
using namespace BearSSL;

#ifdef __cplusplus
extern "C"
{
#endif

    char tchibo_client_session_id[39];
    char *tchibo_public_key;

    typedef struct tchibo_login_result
    {
        bool success;
        String hand_shake_token;
        String security_token;
        bool login_success;
        bool dispatch_success_message;
        bool interested_customer_cookie_flag;
    } tchibo_login_result;

    int tchibo_get_client_session_id(char *buf, size_t buf_len);
    String tchibo_get_public_key(String client_session_id);
    tchibo_login_result tchibo_login_by_password(String encryptedUsername, String encryptedPassword, String client_session_id);
    String test();

    /* ================================================== */
    /* ================================================== */
    /* ================================================== */

#ifndef TCHIBO_NO_IMPL

    HTTPClient https;
    unique_ptr<WiFiClientSecure> client(new WiFiClientSecure);

    int tchibo_get_client_session_id(char *buf, size_t buf_len)
    {

        if (buf == NULL)
        {
            return -1;
        }

        if (buf_len > 0)
        {
            buf[0] = '\0';
        }

        if (buf_len < 40)
        {
            // Buffer too short.
            return -2;
        }

        const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        buf[0] = 't';
        buf[1] = 'm';
        buf[2] = '-';

        for (size_t n = 3; n < 39; n++)
        {
            if (n == 11 || n == 16 || n == 21 || n == 26)
            {
                buf[n] = '-';
            }
            else
            {
                size_t key = (size_t)rand() % (sizeof charset - 1);
                buf[n] = charset[key];
            }
        }

        buf[39] = '\0';

        return 0;
    }

    tchibo_login_result tchibo_login_by_password(String encryptedUsername, String encryptedPassword, String client_session_id)
    {
        tchibo_login_result result;
        if (https.begin(*client, "https://public-service.tchibo-mobil.de/loginservice/jsp/service.jsp"))
        {
            String payload = String("action=submitLoginFormLoginByPassword&clientSessionID=") + client_session_id + "&" + "username=" + encryptedUsername + "&" + "password=" + encryptedPassword;
            int httpCode = https.POST(payload);
            Serial.print("httpCode:");
            Serial.printf("%d \n", httpCode);
            if (httpCode > 0)
            {
                if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
                {
                    String response = https.getString();

                    DynamicJsonDocument doc(384);
                    DeserializationError error = deserializeJson(doc, response);
                    if (error)
                    {
                        Serial.print("deserializeJson() failed: ");
                        Serial.println(error.c_str());
                    }
                    else
                    {
                        result.success = doc["success"];
                        result.hand_shake_token = String(doc["handShakeToken"].as<char *>());
                        result.security_token = String(doc["securityToken"].as<char *>());
                        result.login_success = doc["loginSuccess"];
                        result.dispatch_success_message = doc["dispatchSuccessMessage"];
                        result.interested_customer_cookie_flag = doc["interestedCustomerCookieFlag"];
                    }
                }
            }
            else
            {
                Serial.print("invalid httpCode\n");
            }

            https.end();
        }
        else
        {
            Serial.print("No connection\n");
        }

        return result;
    }

    String test()
    {
        String result;
        if (https.begin(*client, "https://api.chucknorris.io/jokes/random"))
        {
            int httpCode = https.GET();
            Serial.print("httpCode:");
            Serial.printf("%d \n", httpCode);
            if (httpCode > 0)
            {
                if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
                {
                    String response = https.getString();

                    DynamicJsonDocument doc(384);
                    DeserializationError error = deserializeJson(doc, response);
                    if (error)
                    {
                        Serial.print("deserializeJson() failed: ");
                        Serial.println(error.c_str());
                    }
                    else
                    {
                        result = String(doc["success"].as<char *>());
                    }
                }
            }
            else
            {
                Serial.print("invalid httpCode\n");
            }

            https.end();
        }
        else
        {
            Serial.print("No connection\n");
        }

        return result;
    }

#endif // TCHIBO_NO_IMPL

#ifdef __cplusplus
}
#endif

#endif // TCHIBO_WRAPPER_H