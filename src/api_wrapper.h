#ifndef API_WRAPPER_H
#define API_WRAPPER_H

#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>

using namespace std;
using namespace BearSSL;

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct tchibo_tarif_status_result
    {
        int current_value;
        String free_percent;
        bool is_throttled;
        int max_value;
        String used_percent;

    } tchibo_tarif_status_result;

    tchibo_tarif_status_result tchibo_get_tarif_status();

    /* ================================================== */
    /* ================================================== */
    /* ================================================== */

#ifndef TCHIBO_NO_IMPL

    WiFiClientSecure client;
    HTTPClient http;

    String baseUrl;

    tchibo_tarif_status_result tchibo_get_tarif_status()
    {
        http.useHTTP10(true);
        //client.setInsecure();
        tchibo_tarif_status_result result;

        String test = baseUrl + "/tarifstatus";
        Serial.println(test);

        if (http.begin(client, test))
        {
            int httpCode = http.GET();
            Serial.println(httpCode);
            if (httpCode > 0)
            {
                if (httpCode == HTTP_CODE_OK)
                {
                    DynamicJsonDocument json(192);
                    DeserializationError error = deserializeJson(json, http.getStream());
                    if (error)
                    {
                        Serial.print("deserialization failed: ");
                        Serial.println(error.c_str());
                    }
                    else
                    {
                        result.current_value = int(json["currentValue"]);
                        result.free_percent = json["freePercent"].as<String>();
                        result.is_throttled = json["isThrottled"];
                        result.max_value = int(json["maxValue"]);
                        result.used_percent = json["usedPercent"].as<String>();
                    }
                }
            }
            else
            {
                Serial.print("Invalid httpCode\n");
            }

            http.end();
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

#endif // API_WRAPPER_H