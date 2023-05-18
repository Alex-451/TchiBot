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
        String remaining_data;
        int remaining_data_in_mb;
        String extends_on;
        bool is_throttled;
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
        client.setInsecure();
        tchibo_tarif_status_result result;

        if (http.begin(client, baseUrl + "/status"))
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
                        result.remaining_data = json["remainingData"].as<String>();
                        result.remaining_data_in_mb = json["remainingDataInMb"].as<int>();
                        result.extends_on = json["extendsOn"].as<String>();
                        result.is_throttled = json["isThrottled"].as<bool>();
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