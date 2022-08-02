#include "WiFiManager.h" // https://github.com/tzapu/WiFiManager
#include <FS.h>          // File System
#include "FS.h"          // File System
#include <ArduinoJson.h> // Arduino JSON
#include <ESP8266WiFi.h>
#include <BearSSLHelpers.h>
#include <bearssl/bearssl.h>
#include <derdec.h>
#include <tchibo_wrapper.h>

#pragma region JSON

// JSON configuration file
#define JSON_CONFIG_FILE "/config.json"

// Flag for saving data
bool isSavingConfig = false;

// Variables to hold data
char userName[50] = "";
char password[50] = "";
char encryptedUserName[513] = "";
char encryptedPassword[513] = "";

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
  File configFile = SPIFFS.open(JSON_CONFIG_FILE, "w");
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

  if (SPIFFS.begin())
  {
    Serial.println("Mounted file system");
    if (SPIFFS.exists(JSON_CONFIG_FILE))
    {
      Serial.println("Reading config file");
      File configFile = SPIFFS.open(JSON_CONFIG_FILE, "r");
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

          strcpy(userName, json["userName"]);
          strcpy(password, json["password"]);
          // strcpy(encryptedUserName, json["encryptedUserName"]);
          // strcpy(encryptedPassword, json["encryptedPassword"]);
          *encryptedUserName = json["encryptedUserName"];
          *encryptedPassword = json["encryptedPassword"];

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

#pragma endregion

#pragma region ENCRYPT

static const uint8_t raw_pkey[] = {
    0x30,
    0x82,
    0x01,
    0x21,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
    0x03,
    0x82,
    0x01,
    0x0e,
    0x00,
    0x30,
    0x82,
    0x01,
    0x09,
    0x02,
    0x82,
    0x01,
    0x00,
    0x5e,
    0xcf,
    0xd3,
    0x17,
    0xf4,
    0xdc,
    0xc6,
    0x6a,
    0xc4,
    0xff,
    0xc2,
    0x53,
    0x0a,
    0x80,
    0xb3,
    0xcb,
    0x0a,
    0xdd,
    0xf3,
    0x83,
    0xe3,
    0xa6,
    0x94,
    0x99,
    0x8f,
    0xf9,
    0x08,
    0x11,
    0x4a,
    0x46,
    0xdf,
    0x17,
    0x86,
    0xe0,
    0xc2,
    0x54,
    0x6a,
    0xae,
    0x06,
    0xe8,
    0xc9,
    0x31,
    0xf5,
    0x91,
    0xdb,
    0x4a,
    0x27,
    0xaf,
    0x83,
    0x9a,
    0x26,
    0xb3,
    0x6c,
    0xa1,
    0xe4,
    0x2c,
    0xc8,
    0x49,
    0xba,
    0x57,
    0xa8,
    0x7e,
    0x42,
    0xa5,
    0x7e,
    0xd6,
    0xce,
    0xed,
    0x3e,
    0xde,
    0xa5,
    0xa2,
    0x46,
    0xeb,
    0x04,
    0xab,
    0x33,
    0x72,
    0xc3,
    0x7e,
    0x56,
    0xce,
    0x3d,
    0xc4,
    0xe1,
    0x28,
    0xe7,
    0x92,
    0xa7,
    0x54,
    0x20,
    0xd0,
    0x92,
    0x91,
    0x82,
    0x59,
    0x42,
    0xc7,
    0x31,
    0xe0,
    0x4b,
    0xaa,
    0xdc,
    0xc8,
    0xee,
    0x3e,
    0xe6,
    0xf3,
    0x64,
    0x79,
    0x69,
    0xe1,
    0x6e,
    0x23,
    0x53,
    0xac,
    0x12,
    0x27,
    0x51,
    0xee,
    0xcf,
    0x0a,
    0x99,
    0x3b,
    0x36,
    0xe4,
    0x51,
    0x2a,
    0x31,
    0xfc,
    0x52,
    0x6e,
    0x61,
    0x4e,
    0xa4,
    0x6f,
    0x1f,
    0x55,
    0xb1,
    0x7c,
    0xef,
    0x60,
    0xbe,
    0xa3,
    0xe3,
    0xe7,
    0x2e,
    0x23,
    0x52,
    0x16,
    0x6c,
    0xf4,
    0x0f,
    0xd4,
    0xbf,
    0xbf,
    0x0d,
    0x3c,
    0xd6,
    0xe2,
    0xf6,
    0x2d,
    0xc3,
    0x3c,
    0xf3,
    0x76,
    0x54,
    0x86,
    0xb5,
    0xdc,
    0x35,
    0x0b,
    0xe6,
    0xfd,
    0x42,
    0xb9,
    0xf6,
    0x5d,
    0x67,
    0x41,
    0x1a,
    0x4a,
    0x71,
    0x55,
    0xd0,
    0xc2,
    0x20,
    0x44,
    0x98,
    0x98,
    0x52,
    0x0e,
    0x8a,
    0x44,
    0x53,
    0x3d,
    0xb5,
    0x4e,
    0x07,
    0x37,
    0x09,
    0xbc,
    0xe5,
    0xe3,
    0xeb,
    0x07,
    0x7e,
    0x8b,
    0x40,
    0xea,
    0x75,
    0x2d,
    0x80,
    0x2c,
    0x42,
    0xe1,
    0xaf,
    0xbe,
    0xbe,
    0x74,
    0x6f,
    0xc9,
    0xf7,
    0x13,
    0xe5,
    0x8e,
    0xc8,
    0xd1,
    0x1a,
    0x74,
    0xa1,
    0xe7,
    0x32,
    0x53,
    0x2d,
    0x63,
    0x91,
    0x0c,
    0x3f,
    0x55,
    0xca,
    0xa0,
    0xbe,
    0xb8,
    0xe8,
    0x40,
    0xb7,
    0x8c,
    0x13,
    0x8b,
    0xd5,
    0xa5,
    0x6e,
    0x21,
    0xf5,
    0x6f,
    0x02,
    0x03,
    0x01,
    0x00,
    0x01,
};
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

  if (derdec_pkcs1(buf, buf_len, (const uint8_t *)plaintext, plaintext_len,
                   0) != DERDEC_OK)
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

#pragma endregion

void setup()
{
  bool forceConfig = false;

  bool spiffsSetup = loadConfig();
  if (!spiffsSetup)
  {
    Serial.println(F("Forcing config mode as there is no saved config"));
    forceConfig = true;
  }

  WiFi.mode(WIFI_STA); // explicitly set mode, esp defaults to STA+AP

  // put your setup code here, to run once:
  Serial.begin(115200);

  // WiFiManager, Local intialization. Once its business is done, there is no need to keep it around
  WiFiManager wm;

  // reset settings - wipe stored credentials for testing
  // these are stored by the esp library
  wm.resetSettings();

  // Set config save notify callback
  wm.setSaveConfigCallback(saveConfigCallback);

  // Set callback that gets called when connecting to previous WiFi fails, and enters Access Point mode
  wm.setAPCallback(configModeCallback);

  // Custom parameters
  // id/name, placeholder/prompt, default, length
  WiFiManagerParameter tchibo_user_name("user_name", "Tchibo phone number/EMail address", userName, 50);
  WiFiManagerParameter tchibo_password("password", "Tchibo password", password, 50);

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
  Serial.println("");
  Serial.println("WiFi connected");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Copy the string value
  strncpy(userName, tchibo_user_name.getValue(), sizeof(userName));
  strncpy(password, tchibo_password.getValue(), sizeof(password));

  Serial.print("Client session id:");
  srand(time(NULL));

  char sid[40];
  for (size_t i = 0; i < 5; i++)
  {
    if (tchibo_get_client_session_id(sid, sizeof(sid)) != 0)
    {
      fprintf(stderr, "oh no.\n");
    }

    printf("%s\n", sid);
  }

  Serial.print("userName: ");
  Serial.println(userName);

  Serial.print("password: ");
  Serial.println(password);

  Serial.print("encrypted userName: ");
  Serial.println(encryptedUserName);

  Serial.print("encrypted password: ");
  Serial.println(encryptedPassword);

  // Save the custom parameters to FS
  if (isSavingConfig)
  {
    saveConfig();
  }
}

void loop()
{
  // put your main code here, to run repeatedly:
}