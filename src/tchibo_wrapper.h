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
        char hand_shake_token[36];
        char security_token[36];
        bool login_success;
        bool dispatch_success_message;
        bool interested_customer_cookie_flag;
    } tchibo_login_result;

    int tchibo_get_client_session_id(char *buf, size_t buf_len);
    char *tchibo_get_public_key();
    tchibo_login_result tchibo_login_by_password(char username[513], char password[513], char client_session_id[39]);

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

#endif // TCHIBO_NO_IMPL

#ifdef __cplusplus
}
#endif

#endif // TCHIBO_WRAPPER_H