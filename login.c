#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef DISABLE_CHANGE_PASSWORD
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#endif

#include <windows.h>
#include <wincrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>


#include "main.h"
#include "options.h"
#include "login.h"
#include "openvpn.h"
#include "openvpn-gui-res.h"
#include "chartable.h"
#include "localization.h"
#include "misc.h"

extern options_t o;

#define SKIP_PEER_VERIFICATION
#define SKIP_HOSTNAME_VERIFICATION

static const char* grant_type = "password";
static const char* client_id = "enterprise-app";
static const char* client_secret = "dde2bea7-29b9-492a-aaae-5450b0e72d53";


bool Login(char* username, char* password) {
    CURL* curl;
    CURLcode res;

    struct curl_slist* headers = NULL;                      /* http headers to send with request */


    bool ret = false;

    /* Apriamo un file che conterra la nostra pagina scaricata */
    FILE* f = fopen("log.txt", "w");
    if (f == NULL) {
        curl_easy_cleanup(curl);
        return -1;
    }


    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");


    const char* post_fields_template = "grant_type=&client_id=&client_secret=&username=&password=";

    int post_fields_len = strlen(post_fields_template) + strlen(grant_type) + strlen(client_id) + strlen(client_secret) + strlen(username) + strlen(password) + 1;

    char* post_fields = malloc(post_fields_len);

    if (post_fields != NULL) {
        sprintf(post_fields, "grant_type=%s&client_id=%s&client_secret=%s&username=%s&password=%s", grant_type, client_id, client_secret, username, password);
        fprintf(f, post_fields);
    } else {
        sprintf(stderr, "Menmory alloc failed !\n");
        ret = false;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if (curl) {
        //curl_easy_setopt(curl, CURLOPT_POST, 1L);

        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.2.25:8080/auth/realms/sypnos/protocol/openid-connect/token");
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);



#ifdef SKIP_PEER_VERIFICATION
        /*
         * If you want to connect to a site who isn't using a certificate that is
         * signed by one of the certs in the CA bundle you have, you can skip the
         * verification of the server's certificate. This makes the connection
         * A LOT LESS SECURE.
         *
         * If you have a CA cert for the server stored someplace else than in the
         * default bundle, then the CURLOPT_CAPATH option might come handy for
         * you.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
        /*
         * If the site you're connecting to uses a different host name that what
         * they have mentioned in their server certificate's commonName (or
         * subjectAltName) fields, libcurl will refuse to connect. You can skip
         * this check, but this will make the connection less secure.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

        /* Esegue tutte le istruzioni che abbiam dati fin ora, res conterra
         * il codice d'errore */
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code == 200) {
                ret = true;
            }
        } else {
            sprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            ret = false;
        }

        /* free headers */
        curl_slist_free_all(headers);

        /* Pulisce il nostro handle  */
        curl_easy_cleanup(curl);

        curl_global_cleanup();
    }

    fclose(f);

    return ret;
}

//WCHAR error[50];

static size_t writecallback(void* buffer, size_t size, size_t nmemb, void* stream);
int progress(void* ptr, double t, /* dltotal */
    double d, /* dlnow */
    double ultotal,
    double ulnow);


int getConfig(void)
{
    CURL* curl;
    CURLcode res;

    int ret = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);


    curl = curl_easy_init();
    if (curl) {

        /*
        curl_easy_setopt(curl, CURLOPT_URL, "https://192.168.200.115:8080/appliances");
        curl_easy_setopt(curl, CURLOPT_USERNAME, "myusername");
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "mypassword");
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        */

        /*Settiamo la URL del nostro file*/
        //curl_easy_setopt(curl, CURLOPT_URL, "http://www.africau.edu/images/default/sample.pdf");
        //curl_easy_setopt(curl, CURLOPT_URL, "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf");
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com");
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

#ifdef SKIP_PEER_VERIFICATION
        /*
         * If you want to connect to a site who isn't using a certificate that is
         * signed by one of the certs in the CA bundle you have, you can skip the
         * verification of the server's certificate. This makes the connection
         * A LOT LESS SECURE.
         *
         * If you have a CA cert for the server stored someplace else than in the
         * default bundle, then the CURLOPT_CAPATH option might come handy for
         * you.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
        /*
         * If the site you're connecting to uses a different host name that what
         * they have mentioned in their server certificate's commonName (or
         * subjectAltName) fields, libcurl will refuse to connect. You can skip
         * this check, but this will make the connection less secure.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif



        /* Apriamo un file che conterra la nostra pagina scaricata */
        FILE* f = fopen("file.txt", "w");
        if (f == NULL) {
            curl_easy_cleanup(curl);
            return -1;
        }

        /* Con questa istruzione scriviamo i dati catturati dall'url nel file f */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecallback);

        /*Per l'avanzamento dello stato del dowload*/
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress);

        /* Esegue tutte le istruzioni che abbiam dati fin ora, res conterra
         * il codice d'errore */
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            //sprintf(error, "curl_easy_perform() failed: %s\n",
            //    curl_easy_strerror(res));
            fprintf(f, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
            ret = res;
        }

        /* Pulisce il nostro handle  */
        curl_easy_cleanup(curl);

        curl_global_cleanup();

        fclose(f);

    }
    return ret;
}


size_t writecallback(void* buffer, size_t size, size_t nmemb, void* stream) {

    int written = fwrite(buffer, size, nmemb, (FILE*)stream);
    return written;
}

int progress(void* ptr,
    double t, /* dltotal */
    double d, /* dlnow */
    double ultotal,
    double ulnow)
{

    /*Progresso in Kilobyte*/
    //printf("Dl->%4.2f kb di %d kb\n",d/1024, (int)t/1024);

        /*Progresso in percentuale*/
    double percento = d * 100 / t;
    printf("Scaricato il %d% \n", (int)percento);

    return 0;

}



/*
 * Return TRUE if login success
 */
static int LoginSuccess(HWND hwndDlg) {
    int MAX_CHAR = 100;
    TCHAR username[MAX_CHAR];
    TCHAR password[MAX_CHAR];

    BOOL success;

    GetDlgItemText(hwndDlg, IDC_EDT_USERNAME, username, _countof(username) - 1);
    GetDlgItemText(hwndDlg, IDC_EDT_PASSWORD, password, _countof(password) - 1);

    
    // Converts TCHAR arrays to char arrays

    char uname[MAX_CHAR + 1];
    char pass[MAX_CHAR + 1];

    /* Convert Unicode to ASCII (CP850) */
    ConvertUnicode2Ascii(username, uname, sizeof(uname));
    ConvertUnicode2Ascii(password, pass, sizeof(pass));

   //wcstombs(uname, username, MAX_CHAR + 1);
    //wcstombs(pass, password, MAX_CHAR + 1);

    //MessageBox(NULL, pass, TEXT("Error"), 0);

    success = Login(uname, pass);

    return success;
}


INT_PTR CALLBACK LoginDialogFunc(HWND hwndDlg, UINT msg, WPARAM wParam, UNUSED LPARAM lParam) {
    HICON hIcon;
    TCHAR keyfile[MAX_PATH];
    int keyfile_format;
    BOOL Translated;

    switch (msg) {

    case WM_INITDIALOG:
        hIcon = LoadLocalizedIcon(ID_ICO_APP);
        if (hIcon) {
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)(ICON_SMALL), (LPARAM)(hIcon));
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)(ICON_BIG), (LPARAM)(hIcon));
        }
        return FALSE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {

        case IDC_EDT_USERNAME:
        case IDC_EDT_PASSWORD:
            if (HIWORD(wParam) == EN_UPDATE) {
                /* enable OK if response is non-empty */
                //BOOL enableOK = GetWindowTextLength((HWND)lParam);
                HWND hwndUsernameEDT = GetDlgItem(hwndDlg, IDC_EDT_USERNAME);
                HWND hwndPasswordEDT = GetDlgItem(hwndDlg, IDC_EDT_PASSWORD);
                BOOL enableOK = GetWindowTextLength(hwndUsernameEDT) && GetWindowTextLength(hwndPasswordEDT);
                EnableWindow(GetDlgItem(hwndDlg, IDOK), enableOK);
            }
            break;

        case IDOK:

            /* Check if login success. */
            if (!LoginSuccess(hwndDlg)) {
              /* passwords don't match */
              ShowLocalizedMsg(IDS_ERR_LOGIN_FAILED);
              break;
            }

            DestroyWindow(hwndDlg);
            break;

        case IDCANCEL:
            DestroyWindow(hwndDlg);
            break;
        }

        break;


    case WM_DESTROY:
        PostQuitMessage(0);
        break;


    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        return FALSE;

    }

    return FALSE;
}



static DWORD WINAPI LoginThread(LPVOID data) {
    HWND hwndLogin;
    MSG messages;
    //TCHAR conn_name[100];
    //TCHAR keyfilename[MAX_PATH];
    //int keyfile_format = 0;
    //connection_t* c = data;

    /* Cut of extention from config filename. */
    //_tcsncpy(conn_name, c->config_file, _countof(conn_name));
    //conn_name[_tcslen(conn_name) - (_tcslen(o.ext_string) + 1)] = 0;

    /* Get Key filename from config file */
    //if (!GetKeyFilename(c, keyfilename, _countof(keyfilename), &keyfile_format, false)) {
    //    ExitThread(1);
    //}

    /* Show Login Dialog */
    hwndLogin = CreateLocalizedDialog(IDC_DLG_LOGIN, LoginDialogFunc);
    if (!hwndLogin) {
        ExitThread(1);
    }

    //SetDlgItemText(hwndLogin, ID_TXT_KEYFILE, keyfilename);
    //SetDlgItemInt(hwndLogin, ID_TXT_KEYFORMAT, (UINT)keyfile_format, FALSE);

    //SetWindowText(hwndLogin, LoadLocalizedString(IDS_NFO_CHANGE_PWD, conn_name));

    ShowWindow(hwndLogin, SW_SHOW);


    /* Run the message loop. It will run until GetMessage() returns 0 */
    while (GetMessage(&messages, NULL, 0, 0)) {
        if (!IsDialogMessage(hwndLogin, &messages)) {
            TranslateMessage(&messages);
            DispatchMessage(&messages);
        }
    }

    CloseHandle(hwndLogin);
    ExitThread(0);
}

void ShowLoginDialog(connection_t* c) {
    HANDLE hThread;
    DWORD IDThread;

    /* Start a new thread to have our own message-loop for this dialog */
    hThread = CreateThread(NULL, 0, LoginThread, 0, 0, &IDThread);
    if (hThread == NULL) {
        /* error creating thread */
        ShowLocalizedMsg(IDS_ERR_CREATE_LOGIN_THREAD);
        return;
    }
    CloseHandle(hThread);
}