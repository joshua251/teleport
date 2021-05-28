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

#include "main.h"
#include "options.h"
#include "login.h"
#include "openvpn.h"
#include "openvpn-gui-res.h"
//#include "chartable.h"
#include "localization.h"
#include "misc.h"

extern options_t o;


/*
 * Return TRUE if login success
 */
static int LoginSuccess(HWND hwndDlg) {
    TCHAR username[50];
    TCHAR password[50];

    BOOL success = false;

    GetDlgItemText(hwndDlg, IDC_EDT_USERNAME, username, _countof(username) - 1);
    GetDlgItemText(hwndDlg, IDC_EDT_PASSWORD, password, _countof(password) - 1);

    // WRITE HERE AUTHENTICATION SERVICE CALL

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
    TCHAR conn_name[100];
    TCHAR keyfilename[MAX_PATH];
    int keyfile_format = 0;
    connection_t* c = data;

    /* Cut of extention from config filename. */
    _tcsncpy(conn_name, c->config_file, _countof(conn_name));
    conn_name[_tcslen(conn_name) - (_tcslen(o.ext_string) + 1)] = 0;

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
    hThread = CreateThread(NULL, 0, LoginThread, c, 0, &IDThread);
    if (hThread == NULL) {
        /* error creating thread */
        ShowLocalizedMsg(IDS_ERR_CREATE_LOGIN_THREAD);
        return;
    }
    CloseHandle(hThread);
}