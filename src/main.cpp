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
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x87, 0x67, 0x98, 0x80, 0x94, 0x18, 0x3b, 0xcf, 0xfa, 0xe5, 0xef, 0x5d, 0xfa, 0xbe, 0xeb, 0xa9, 0x42, 0x30, 0x42, 0x1e, 0x7f, 0x94, 0x7e, 0xab, 0x8d, 0x11, 0x18, 0x1a, 0x63, 0xb4, 0x9e, 0x1e, 0x89, 0xa8, 0x03, 0x2f, 0x1a, 0x13, 0xcf, 0x89, 0xcf, 0x5b, 0x88, 0xa5, 0x09, 0xcd, 0xb2, 0xb3, 0x83, 0xb8, 0xd4, 0x75, 0xf2, 0x6e, 0x20, 0x33, 0x15, 0x09, 0x5c, 0xfc, 0x01, 0xab, 0xb3, 0x7d, 0xb0, 0x11, 0x43, 0xef, 0xe7, 0xc2, 0x7f, 0x74, 0x9f, 0x85, 0xdc, 0xca, 0xba, 0x3d, 0x5a, 0x68, 0x63, 0x58, 0xec, 0xbf, 0xd0, 0x11, 0x27, 0x2d, 0x75, 0x2d, 0xef, 0x82, 0x46, 0xe6, 0x09, 0x49, 0xe4, 0xed, 0x6e, 0xf4, 0x1f, 0x80, 0x23, 0x30, 0x03, 0x98, 0xaf, 0xbe, 0x8f, 0xbf, 0x23, 0x50, 0xfd, 0xf2, 0xf7, 0x4f, 0xde, 0x50, 0x68, 0x2e, 0x4a, 0x4d, 0xcb, 0x68, 0x12, 0x0c, 0x97, 0xb3, 0x9d, 0x43, 0xad, 0xc7, 0x22, 0xf0, 0x5f, 0x6c, 0x0f, 0x67, 0xeb, 0x8a, 0xd1, 0x38, 0x7e, 0x5b, 0x00, 0x43, 0xf9, 0xe0, 0xde, 0x28, 0x7c, 0xbb, 0x98, 0x7f, 0x05, 0x6f, 0x91, 0xc4, 0xd0, 0xbd, 0x0a, 0xb4, 0x23, 0x59, 0x1e, 0x47, 0x30, 0xef, 0xb4, 0x32, 0xa3, 0x19, 0x1c, 0xe4, 0x2a, 0xf7, 0x24, 0x0e, 0x4e, 0x74, 0x9c, 0x19, 0xf3, 0x90, 0xc8, 0xdd, 0xee, 0x5d, 0x41, 0x8c, 0x93, 0x2e, 0xcd, 0x84, 0x6c, 0x29, 0x83, 0x13, 0x13, 0x81, 0x22, 0x95, 0xf5, 0xff, 0x48, 0xfc, 0xd3, 0xe7, 0xdc, 0x54, 0x78, 0x96, 0xb4, 0xda, 0x02, 0xec, 0x3b, 0x35, 0x06, 0xb0, 0x9d, 0x5c, 0x4d, 0x43, 0xa3, 0xb5, 0x89, 0xd5, 0x11, 0x1e, 0x53, 0x2b, 0x78, 0xe1, 0x84, 0x44, 0xf6, 0x5a, 0x75, 0x0c, 0xe7, 0x75, 0x44, 0xe6, 0x3e, 0x1d, 0xa6, 0x94, 0x35, 0xb0, 0x50, 0x61, 0x7e, 0x04, 0x89, 0x15, 0x02, 0x03, 0x01, 0x00, 0x01};
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
      if (buf[i] < 15)
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
      if (buf[i] < 15)
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