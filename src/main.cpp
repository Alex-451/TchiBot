#include <SPI.h>
#include <WiFiManager.h>
#include <epd4in2b_V2.h>
#include <imagedata.h>
#include <epdpaint.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <api_wrapper.h>

#define COLORED 0
#define UNCOLORED 1

#define JSON_CONFIG_FILE "/config.json"

// Global variables
Epd epd;

// Config properties
String apiBaseUrl;
bool forceConfig = false;

void saveConfig()
{
  DynamicJsonDocument json(96);
  json["apiBaseUrl"] = apiBaseUrl;

  // Open config file
  File configFile = LittleFS.open(JSON_CONFIG_FILE, "w");
  if (!configFile)
  {
    // Error, file did not open
    Serial.println("Failed to open config file for writing");
  }

  // Serialize JSON data to write
  serializeJsonPretty(json, Serial);
  if (serializeJson(json, configFile) == 0)
  {
    // Error writing file
    Serial.println(F("Failed to write to file"));
  }

  // Close file
  configFile.close();
}

bool loadConfig()
{
  // SPIFFS.format();
  Serial.println("Mounting file system...");

  if (LittleFS.begin())
  {
    Serial.println("Mounted file system");
    if (LittleFS.exists(JSON_CONFIG_FILE))
    {
      Serial.println("Reading config file");
      File configFile = LittleFS.open(JSON_CONFIG_FILE, "r");
      if (configFile)
      {
        Serial.println("Opened configuration");
        DynamicJsonDocument json(128);
        DeserializationError error = deserializeJson(json, configFile);
        serializeJsonPretty(json, Serial);
        if (!error)
        {
          Serial.println("Parsing JSON");

          apiBaseUrl = String(json["apiBaseUrl"].as<String>());
          return true;
        }
        else
        {
          Serial.println("Failed to load JSON configuration");
        }
      }
    }
  }
  else
  {
    Serial.println("Failed to mount file system");
  }
  return false;
}

void setup()
{
  Serial.begin(115200);

  bool spiffsSetup = loadConfig();
  if (!spiffsSetup)
  {
    Serial.println(F("Forcing config mode as there is no saved config"));
    forceConfig = true;
  }

  WiFi.mode(WIFI_STA);

  WiFiManager wifiManager;
  // wifiManager.resetSettings();

  WiFiManagerParameter apiBaseUrlParameter("api_server", "API Url", apiBaseUrl.c_str(), 100);

  wifiManager.addParameter(&apiBaseUrlParameter);

  bool isConnected = false;
  isConnected = wifiManager.autoConnect("TchiBot");

  if (!isConnected)
  {
    Serial.println("Failed to connect");
  }
  else
  {
    Serial.println("");
    Serial.println("WiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
  }

  apiBaseUrl = String(apiBaseUrlParameter.getValue());

  saveConfig();

  if (epd.Init() != 0)
  {
    Serial.print("e-Paper init failed");
    return;
  }

  baseUrl = apiBaseUrl;
  Serial.println("bababaiey");
  Serial.println(tchibo_get_tarif_status().used_percent.c_str());

  /* This clears the SRAM of the e-paper display */
  epd.ClearFrame();

  unsigned char image[1500];
  Paint paint(image, 400, 28); // width should be the multiple of 8

  paint.Clear(COLORED);
  paint.DrawStringAt(50, 4, "Tchibo data volume", &Font24, UNCOLORED);
  epd.SetPartialWindowRed(paint.GetImage(), 0, 40, paint.GetWidth(), paint.GetHeight());

  paint.SetWidth(64);
  paint.SetHeight(64);

  paint.Clear(COLORED);
  // paint.DrawStringAt(0, 0, tchibo_get_tarif_status().used_percent.c_str(), &Font24, UNCOLORED);
  epd.SetPartialWindowRed(paint.GetImage(), 160, 120, paint.GetWidth(), paint.GetHeight());

  // Bottom text
  paint.SetWidth(400);
  paint.SetHeight(28);

  paint.Clear(COLORED);
  paint.DrawStringAt(20, 4, "Extends on 04.04.2023", &Font24, UNCOLORED);
  epd.SetPartialWindowRed(paint.GetImage(), 0, 232, paint.GetWidth(), paint.GetHeight());

  epd.DisplayFrame();

  /* Deep sleep */
  epd.Sleep();
}

void loop()
{
  Serial.println(tchibo_get_tarif_status().used_percent.c_str());
}
