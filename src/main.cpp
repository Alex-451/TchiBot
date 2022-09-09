#include "WiFiManager.h" // https://github.com/tzapu/WiFiManager
#include <DNSServer.h>
#include "LittleFS.h"    // File System
#include <ArduinoJson.h> // Arduino JSON
#include <derdec.h>
#include <tchibo_wrapper.h>
#include <SPI.h>
#include "epd4in2b_V2.h"
#include "epdpaint.h"
#include <NTPClient.h>
#include <WiFiUdp.h>
#include <libb64/cdecode.h>
#include <vector>
#include <Regexp.h>

#define COLORED 0
#define UNCOLORED 1

#pragma region JSON

// JSON configuration file
#define JSON_CONFIG_FILE "/config.json"

// Flag for saving data
bool isSavingConfig = false;
bool forceConfig = false;

// Variables to hold data
// char userName[50] = "";
// char password[50] = "";
// char encryptedUserName[513] = "";
// char encryptedPassword[513] = "";#

String userName;
String password;
String encryptedUserName;
String encryptedPassword;

void saveConfig()
{
  Serial.println(F("Saving configuration..."));

  // Create a JSON document
  // StaticJsonDocument<1536> json;
  DynamicJsonDocument json(1536);
  json["userName"] = userName;
  json["password"] = password;
  json["encryptedUserName"] = encryptedUserName;
  json["encryptedPassword"] = encryptedPassword;

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
        // StaticJsonDocument<1536> json;
        DynamicJsonDocument json(1536);
        DeserializationError error = deserializeJson(json, configFile);
        serializeJsonPretty(json, Serial);
        if (!error)
        {
          Serial.println("Parsing JSON");

          // strcpy(userName, json["userName"]);
          // strcpy(password, json["password"]);
          // strcpy(encryptedUserName, json["encryptedUserName"]);
          // strcpy(encryptedPassword, json["encryptedPassword"]);

          userName = String(json["userName"].as<char *>());
          password = String(json["password"].as<char *>());
          encryptedUserName = String(json["encryptedUserName"].as<char *>());
          encryptedPassword = String(json["encryptedPassword"].as<char *>());

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

#pragma endregion

#pragma region NETWORKMANAGER

void saveConfigCallback()
{
  isSavingConfig = true;
}

void configModeCallback(WiFiManager *wifiManager)
{
  Serial.println("Entered Configuration Mode");

  Serial.print("Config SSID: ");
  Serial.println(wifiManager->getConfigPortalSSID());

  Serial.print("Config IP Address: ");
  Serial.println(WiFi.softAPIP());
}

void setup_networkmanager()
{
  Serial.setDebugOutput(true);
  WiFi.mode(WIFI_STA); // explicitly set mode, esp defaults to STA+AP

  // WiFiManager, Local intialization. Once its business is done, there is no need to keep it around
  WiFiManager wm;

  // reset settings - wipe stored credentials for testing
  // these are stored by the esp library
  // wm.resetSettings();

  // Set config save notify callback
  wm.setSaveConfigCallback(saveConfigCallback);

  // Set callback that gets called when connecting to previous WiFi fails, and enters Access Point mode
  wm.setAPCallback(configModeCallback);

  // Custom parameters
  // id/name, placeholder/prompt, default, length
  WiFiManagerParameter tchibo_user_name("user_name", "Tchibo phone number/EMail address", userName.c_str(), 50);
  WiFiManagerParameter tchibo_password("password", "Tchibo password", password.c_str(), 50);

  wm.addParameter(&tchibo_user_name);
  wm.addParameter(&tchibo_password);

  if (forceConfig)
  {
    if (!wm.startConfigPortal("TchiboAP", "TchiboMobile"))
    {
      Serial.println("failed to connect and hit timeout");
      delay(3000);
      // reset and try again, or maybe put it to deep sleep
      ESP.restart();
      delay(5000);
    }
  }
  else
  {
    if (!wm.autoConnect("TchiboAP", "TchiboMobile"))
    {
      Serial.println("failed to connect and hit timeout");
      delay(3000);
      // if we still have not connected restart and try all over again
      ESP.restart();
      delay(5000);
    }
  }

  // If we get here, we are connected to the WiFi
  Serial.println("WiFi connected");

  // Copy the string value
  userName = String(tchibo_user_name.getValue());
  password = String(tchibo_password.getValue());
}

#pragma endregion

#pragma region ENCRYPT

static const uint8_t raw_pkey[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb3, 0x0d, 0x79, 0xb4, 0x9a, 0xdb, 0x5c, 0x45, 0x38, 0xdf, 0x98, 0x1e, 0xf2, 0x53, 0xdf, 0x1c, 0xc2, 0x7e, 0x65, 0x85, 0x33, 0xc9, 0x66, 0xf7, 0x3b, 0xce, 0xee, 0x47, 0xd3, 0x61, 0x64, 0x3e, 0x8e, 0x42, 0x0d, 0x17, 0x3c, 0x88, 0xcf, 0xf2, 0x97, 0xf0, 0x32, 0x31, 0x16, 0x4c, 0xf7, 0xff, 0x95, 0x60, 0x13, 0xe1, 0x21, 0xd3, 0x31, 0xb1, 0xf4, 0xe5, 0xb5, 0x7a, 0x77, 0x8d, 0x4c, 0xa8, 0xf1, 0xbf, 0x4c, 0xce, 0xd0, 0x20, 0xbe, 0x0d, 0x12, 0x41, 0xf7, 0x1e, 0x52, 0x95, 0x4f, 0xc1, 0x94, 0x3b, 0x1b, 0xe2, 0x02, 0x6d, 0x4e, 0x55, 0xa3, 0xaa, 0x69, 0x7d, 0x18, 0x03, 0x7f, 0xa6, 0x97, 0xc5, 0xd1, 0x77, 0x72, 0xef, 0x57, 0xb8, 0xda, 0xba, 0xb4, 0x87, 0x51, 0x35, 0x49, 0xc4, 0x4b, 0xc5, 0x14, 0xb1, 0x62, 0x5f, 0xaa, 0x2b, 0x41, 0x3c, 0xb7, 0x65, 0x8d, 0x28, 0xba, 0x35, 0xf1, 0xe7, 0x3f, 0x00, 0xaf, 0xef, 0x6d, 0xd2, 0xc1, 0x75, 0x23, 0xdf, 0x8d, 0x3c, 0x25, 0x69, 0x8a, 0xf0, 0x69, 0x1a, 0x41, 0x39, 0x2f, 0x4f, 0x79, 0x30, 0xe3, 0xa0, 0x1c, 0x41, 0x3b, 0x49, 0x73, 0x58, 0x46, 0xde, 0x22, 0x1a, 0x66, 0x53, 0xa5, 0x24, 0x9d, 0xcb, 0x7d, 0x54, 0x49, 0xdb, 0x9d, 0x0d, 0x40, 0xdd, 0xcf, 0x78, 0x98, 0x84, 0x44, 0xa8, 0x1a, 0x8e, 0x48, 0x7a, 0xf7, 0x51, 0x7c, 0x34, 0xa9, 0x85, 0xed, 0xf5, 0x8e, 0xcd, 0x24, 0x24, 0x96, 0x81, 0x42, 0xc8, 0xa5, 0x6b, 0x5f, 0xe3, 0x56, 0x37, 0xab, 0x43, 0x8e, 0x8d, 0xdc, 0xa5, 0x9d, 0xc1, 0xad, 0xe9, 0x50, 0xdf, 0x6b, 0x74, 0x3d, 0x5d, 0x5e, 0x5a, 0x2c, 0xa6, 0x07, 0xe6, 0xd1, 0x1b, 0xf1, 0xfa, 0x08, 0xa6, 0x2f, 0xba, 0x13, 0x56, 0xbf, 0x67, 0x82, 0x05, 0xc9, 0x0f, 0x5f, 0xf3, 0xea, 0xec, 0x17, 0x59, 0x02, 0x03, 0x01, 0x00, 0x01};
static const size_t raw_pkey_len = sizeof(raw_pkey);

int encrypt_with_bear(uint8_t *buf, size_t buf_len, const char *const plaintext,
                      size_t plaintext_len, const derdec_pkey *const pkey)
{
  if (buf == NULL || buf_len != 256 || plaintext == NULL ||
      plaintext_len == 0 || pkey == NULL)
  {
    // ERROR: invalid arguments.

    return -1;
  }

  memset(buf, 0, buf_len);

  if (plaintext_len > 245)
  {
    // ERROR: plaintext is too long.

    return -2;
  }

  if ((pkey->modulus.start == NULL || pkey->modulus.end == NULL) ||
      (pkey->exponent.start == NULL || pkey->exponent.end == NULL))
  {
    // ERROR: invalid public key given.

    return -3;
  }

  if (derdec_pkcs1(buf, buf_len, (const uint8_t *)plaintext, plaintext_len, (uint32_t)time(NULL)) != DERDEC_OK)
  {
    // ERROR: PKCS#1 encoder has failed.

    return -4;
  }

  const br_rsa_public_key pkey_bear = {
      (unsigned char *)derdec_pkey_modulus(pkey),
      derdec_pkey_modulus_size(pkey),
      (unsigned char *)derdec_pkey_exponent(pkey),
      derdec_pkey_exponent_size(pkey),
  };

  br_rsa_public rsa_pub_engine = br_rsa_public_get_default();

  if (!rsa_pub_engine(buf, buf_len, &pkey_bear))
  {
    // ERROR: BearSSL's RSA-2048 encryption engine has failed.

    return -5;
  }

  // OK: plaintext has been encrypted successfully. Result was saved into `buf`.

  return 0;
}

void encrypt_credentials()
{
  if (encryptedUserName.length() == 0 || encryptedPassword.length() == 0)
  {
    Serial.println("Encrypt");
    derdec_pkey pkey;

    derdec_err err;
    if ((err = derdec_decode_pkey(&pkey, raw_pkey, raw_pkey_len)) != DERDEC_OK)
    {
      fprintf(stderr, "[!] derdec_decode_pkey failed: %s\n", derdec_err_str(err));
    }

    if (!derdec_pkey_is_pkcs1(&pkey))
    {
      fprintf(stderr, "[!] pkey is not a PKCS1 public key\n");
    }

    // Username encryption
    String result = "";
    uint8_t buf[256];
    encryptedUserName = String("");
    if (encrypt_with_bear(buf, sizeof(buf), userName.c_str(), userName.length(), &pkey) != 0)
    {
      fprintf(stderr, "[!] encrypt_with_bear failed\n");
    }

    for (size_t i = 0; i < sizeof(buf); ++i)
    {
      if (buf[i] <= 15)
        result += "0";

      result += String(buf[i], HEX);
    }
    encryptedUserName = result;

    // Password encryption
    result = "";
    encryptedPassword = String("");
    if (encrypt_with_bear(buf, sizeof(buf), password.c_str(), password.length(), &pkey) != 0)
    {
      fprintf(stderr, "[!] encrypt_with_bear failed\n");
    }

    for (size_t i = 0; i < sizeof(buf); ++i)
    {
      if (buf[i] <= 15)
        result += "0";

      result += String(buf[i], HEX);
    }
    encryptedPassword = result;
  }
}

#pragma endregion

void setup()
{
  Serial.begin(115200);

  // ------------------------------------------------
  // WiFi & File system setup
  // ------------------------------------------------

  bool spiffsSetup = loadConfig();
  if (!spiffsSetup)
  {
    Serial.println(F("Forcing config mode as there is no saved config"));
    forceConfig = true;
  }

  setup_networkmanager();

  // ------------------------------------------------
  // ClientSessionID creation
  // ------------------------------------------------

  srand(time(NULL));

  char sid[40];
  if (tchibo_get_client_session_id(sid, sizeof(sid)) != 0)
  {
    fprintf(stderr, "oh no.\n");
  }

  printf("%s\n", sid);

  // ------------------------------------------------
  // Encryption
  // ------------------------------------------------

  encrypt_credentials();

  // ------------------------------------------------
  // Save custom params
  // ------------------------------------------------

  if (isSavingConfig)
  {
    saveConfig();
  }

  // ------------------------------------------------
  // Tchibo API calls
  // ------------------------------------------------

  tchibo_login_result login_result = tchibo_login_by_password(encryptedUserName, encryptedPassword, sid);
  Serial.println("Security Token:");
  Serial.println(login_result.security_token);

  tchibo_tarif_status taruf_result = tchibo_get_tarif_status(sid, login_result.security_token);
  Serial.println("Free space:");
  Serial.println(taruf_result.used_percent);

  // ------------------------------------------------
  // Get time
  // ------------------------------------------------

  WiFiUDP ntpUDP;
  NTPClient timeClient(ntpUDP);
  timeClient.setTimeOffset(7200);

  timeClient.begin();
  timeClient.update();

  String time = String(timeClient.getHours()) + ":" + String(timeClient.getMinutes());

  // ------------------------------------------------
  // Write to screen
  // ------------------------------------------------

  Epd epd;

  if (epd.Init() != 0)
  {
    Serial.print("e-Paper init failed");
    return;
  }

  epd.ClearFrame();

  unsigned char image[1250];
  Paint paint(image, 200, 50); // width should be the multiple of 8 <--- Causes error

  paint.Clear(UNCOLORED);
  paint.DrawStringAt(35, 0, taruf_result.used_percent.c_str(), &Font24, COLORED);
  paint.DrawStringAt(20, 30, time.c_str(), &Font24, COLORED);
  epd.SetPartialWindowBlack(paint.GetImage(), 140, 150, paint.GetWidth(), paint.GetHeight());

  epd.DisplayFrame();

  epd.Sleep();

  // ------------------------------------------------
  // Deep sleep
  // ------------------------------------------------

  ESP.deepSleep(180e7);
}

void loop()
{
  // put your main code here, to run repeatedly:
}