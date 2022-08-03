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

static const uint8_t raw_pkey[] = {
    0x30,
    0x82,
    0x01,
    0x22,
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
    0x0f,
    0x00,
    0x30,
    0x82,
    0x01,
    0x0a,
    0x02,
    0x82,
    0x01,
    0x01,
    0x00,
    0xd3,
    0x8a,
    0xbe,
    0x22,
    0xd2,
    0x31,
    0x3c,
    0xdd,
    0xd0,
    0xe3,
    0x9a,
    0xc2,
    0xb6,
    0x63,
    0x89,
    0xfe,
    0xdc,
    0x83,
    0x03,
    0x76,
    0xfa,
    0xf9,
    0x65,
    0x12,
    0x47,
    0x5a,
    0xcc,
    0xc4,
    0xd0,
    0x8f,
    0x54,
    0x9a,
    0xc5,
    0x0b,
    0x0e,
    0x84,
    0xa5,
    0x11,
    0x9c,
    0x59,
    0x9f,
    0x5f,
    0xcd,
    0x81,
    0x22,
    0xb2,
    0x28,
    0x57,
    0xae,
    0x48,
    0x0b,
    0xb9,
    0x8d,
    0x4e,
    0x7a,
    0x96,
    0x7a,
    0x21,
    0x6d,
    0xbd,
    0x23,
    0xa2,
    0xaa,
    0xfc,
    0x45,
    0x38,
    0x36,
    0xa0,
    0x1f,
    0x76,
    0xb6,
    0xc3,
    0x22,
    0x3e,
    0x4b,
    0xb2,
    0x54,
    0xc1,
    0x32,
    0xfc,
    0x85,
    0xe0,
    0xdf,
    0x02,
    0x29,
    0xfb,
    0xed,
    0x9a,
    0xfc,
    0x0d,
    0xbe,
    0x1c,
    0xd9,
    0x2a,
    0x9c,
    0x10,
    0xa3,
    0x2f,
    0xd4,
    0x14,
    0x89,
    0x4b,
    0x21,
    0x00,
    0xcc,
    0xea,
    0x81,
    0x90,
    0xf6,
    0xd1,
    0x69,
    0xcc,
    0x98,
    0x67,
    0x5e,
    0x1c,
    0x3f,
    0xa1,
    0x56,
    0xfb,
    0x68,
    0x94,
    0xf4,
    0xa7,
    0xa6,
    0x70,
    0x26,
    0xac,
    0x77,
    0x69,
    0x1a,
    0x60,
    0xbc,
    0xb9,
    0xbf,
    0xf8,
    0xee,
    0x50,
    0x53,
    0xa4,
    0x95,
    0x2e,
    0xc7,
    0xd1,
    0x0d,
    0xdb,
    0xae,
    0xde,
    0x8b,
    0xf1,
    0xec,
    0xc9,
    0xb5,
    0x35,
    0xfc,
    0x39,
    0x0e,
    0x3a,
    0x2e,
    0x39,
    0x34,
    0x15,
    0x97,
    0x09,
    0xa5,
    0x2a,
    0xbe,
    0x5b,
    0x61,
    0x07,
    0xe0,
    0x7c,
    0x2b,
    0x6d,
    0x44,
    0x7c,
    0xa0,
    0x44,
    0x6e,
    0xae,
    0xb6,
    0x6f,
    0x36,
    0xf2,
    0xec,
    0x21,
    0x4a,
    0xd5,
    0xe1,
    0x01,
    0xe3,
    0x89,
    0xfe,
    0xc3,
    0x8b,
    0xeb,
    0x01,
    0xe7,
    0x94,
    0x96,
    0x0a,
    0xc5,
    0x01,
    0x96,
    0x9f,
    0x9e,
    0xe3,
    0x2a,
    0x74,
    0xc8,
    0x80,
    0x0d,
    0xc5,
    0x08,
    0xa4,
    0xa9,
    0x17,
    0xe4,
    0xde,
    0xfb,
    0x5e,
    0x25,
    0x27,
    0xc2,
    0x43,
    0x44,
    0xd4,
    0x40,
    0x42,
    0x37,
    0x91,
    0x80,
    0x02,
    0x34,
    0x4f,
    0x4f,
    0xfa,
    0x4b,
    0xec,
    0xfb,
    0x9a,
    0xac,
    0x36,
    0xb5,
    0x42,
    0x09,
    0xcd,
    0x16,
    0x68,
    0x44,
    0x13,
    0x37,
    0xd6,
    0x36,
    0x80,
    0x23,
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

  Serial.print("Encrypter username:");
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
  const char *plaintext = "015150355284";

  uint8_t buf[256];
  if (encrypt_with_bear(buf, sizeof(buf), plaintext, strlen(plaintext),
                        &pkey) != 0)
  {
    fprintf(stderr, "[!] encrypt_with_bear failed\n");
  }

  for (size_t i = 0; i < sizeof(buf); ++i)
  {
    Serial.printf("%02x", buf[i]);
  }
  printf("\n");

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