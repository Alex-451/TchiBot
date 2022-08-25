#include "WiFiManager.h" // https://github.com/tzapu/WiFiManager
#include <DNSServer.h>
#include "LittleFS.h"    // File System
#include <ArduinoJson.h> // Arduino JSON
#include <derdec.h>
#include <tchibo_wrapper.h>

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
  wm.resetSettings();

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
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x9f, 0x73, 0xa1, 0xfc, 0xc2, 0x2d, 0x0d, 0x16, 0x1a, 0x39, 0xd6, 0x79, 0x08, 0x05, 0xba, 0xa0, 0xc5, 0x32, 0x8a, 0x5e, 0x3e, 0x19, 0x86, 0xc1, 0xc2, 0x9f, 0x72, 0x1f, 0x76, 0xcd, 0xc9, 0xca, 0xc4, 0xe3, 0x89, 0x69, 0xf1, 0x60, 0xa0, 0x7f, 0xba, 0x5e, 0xa5, 0xcf, 0xa5, 0x4c, 0xb4, 0x8c, 0x64, 0xa6, 0xd4, 0xd8, 0x95, 0x2d, 0x11, 0xdb, 0x53, 0x7a, 0xdd, 0x90, 0x84, 0x27, 0x5d, 0xac, 0x33, 0x3c, 0xce, 0x43, 0x34, 0xe1, 0x60, 0x44, 0x5c, 0xe3, 0x32, 0x18, 0xce, 0x69, 0xf8, 0xe0, 0xbe, 0xe5, 0xa1, 0x12, 0x19, 0xff, 0x0c, 0x90, 0x52, 0xd8, 0xdc, 0x39, 0xc9, 0x91, 0xae, 0xc9, 0x16, 0xf6, 0x00, 0x61, 0x00, 0x8e, 0x8b, 0x9f, 0x65, 0x1e, 0x7b, 0x5d, 0x8e, 0xff, 0x9c, 0x0e, 0x13, 0x16, 0x00, 0x25, 0x76, 0x79, 0x8a, 0x15, 0xef, 0x56, 0x37, 0xe7, 0x62, 0x75, 0xb2, 0x7a, 0xe4, 0xf0, 0x1e, 0xd7, 0x9f, 0x27, 0x00, 0x53, 0xc8, 0x63, 0x2f, 0xa3, 0x4a, 0x35, 0x98, 0x6d, 0x2e, 0xa0, 0x78, 0x39, 0x8d, 0x4b, 0xec, 0xde, 0x72, 0x3c, 0x6e, 0x82, 0x02, 0x30, 0x61, 0x55, 0xdb, 0x74, 0xb6, 0x96, 0x9b, 0x1e, 0xd8, 0x16, 0x18, 0x44, 0x59, 0xe6, 0x33, 0x37, 0x2b, 0xad, 0xce, 0xe2, 0x7a, 0xc8, 0x0f, 0xa4, 0xe7, 0xf1, 0x3f, 0x43, 0x17, 0x03, 0x61, 0xbf, 0xfc, 0x2d, 0x0a, 0xe1, 0xba, 0xa8, 0xd3, 0xa2, 0x73, 0xa5, 0xe9, 0x52, 0x81, 0x73, 0xfe, 0xfe, 0x9a, 0xfc, 0x04, 0x6f, 0x78, 0x1a, 0xac, 0xc9, 0x03, 0xcb, 0x4d, 0xab, 0xd2, 0xe8, 0x00, 0x97, 0x76, 0xa9, 0x32, 0xe9, 0xb1, 0xd9, 0x3b, 0x49, 0xe7, 0xc0, 0x32, 0xbe, 0x45, 0x64, 0x7e, 0xfd, 0x43, 0xac, 0x7e, 0x3a, 0x76, 0x30, 0xf3, 0x0d, 0x21, 0x6f, 0xab, 0xa7, 0xad, 0x16, 0x4b, 0x29, 0x3d, 0x73, 0x02, 0x03, 0x01, 0x00, 0x01};
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
}

void loop()
{
  // put your main code here, to run repeatedly:
}