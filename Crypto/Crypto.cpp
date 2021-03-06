#include "stdafx.h"
#include "Crypto.h"
#include "Encrypter.h"
#include "Decrypter.h"

#include <Windows.h>
#include <Commdlg.h>
#include <iostream>

#define MAX_LOADSTRING 100

#define OPEN_FILE_BUTTON 1
#define ENCRYPT_BUTTON 2
#define DECRYPT_BUTTON 3
#define EXIT_BUTTON 4

HWND hStatusLabel;
HWND hPassword;
HWND hFilename;

OPENFILENAME ofn;
wchar_t szFile[MAX_PATH + 1];

OPENFILENAME ofnSave;
wchar_t szFileSave[MAX_PATH + 1];

HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];

ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_CRYPTO, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_CRYPTO));

    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}


ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_CRYPTO));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = NULL;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}


BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance;

   HWND hWnd = CreateWindowW(
		szWindowClass,
		L"File encryptor",
		WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME,
		CW_USEDEFAULT, CW_USEDEFAULT,
		415, 482,
		nullptr, 
		nullptr, 
		hInstance,
		nullptr
   );

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

const wchar_t* getStatusMessage(int code)
{
	switch (code)
	{
	case 0:
		return L"Complited!";
	case 1:
		return L"Cant open source file!";
	case 2:
		return L"Cant open destination file!";
	case 3:
		return L"Error acquiring crypto provider!";
	case 4:
		return L"Error creating session key!";
	case 7:
		return L"Error during CryptImportKey!";
	case 20:
		return L"Error reading key BLOB length!";
	case 21:
		return L"Memory allocation error.";
	case 22:
		return L"Error reading key BLOB length!";
	default:
		return L"Waiting...";
	}
}

void setStatusMessage(int action, int code)
{
	wchar_t str[80];
	wcscpy(str, L"     ");
	switch (action)
	{
	case 0:
		wcscat(str, L"[Encrypting] ");
		break;
	case 1:
		wcscat(str, L"[Decrypting] ");
		break;
	default:
		wcscat(str, L"Waiting");
		SetWindowText(hStatusLabel, (LPTSTR)str);
		return;
	}
	wcscat(str, getStatusMessage(code));
	SetWindowText(hStatusLabel, (LPTSTR)str);
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{ 
    switch (message)
    {
	case WM_CREATE:
		{
			HWND hTitle = CreateWindow(TEXT("STATIC"), TEXT("FILE ENCRYPTOR"),
				WS_VISIBLE | WS_CHILD | SS_CENTER,
				0, 30, 400, 24,
				hWnd, (HMENU) NULL, NULL, NULL
			);

			HWND hDescription = CreateWindow(TEXT("STATIC"), TEXT("Encrypt important personal information to protect it"),
				WS_VISIBLE | WS_CHILD | SS_CENTER,
				0, 54, 400, 18,
				hWnd, (HMENU) NULL, NULL, NULL
			);

			// Step 1: select file
			int stepPosition1 = 90;
			HWND hStep1 = CreateWindow(TEXT("STATIC"), TEXT("Step 1: Open file"),
				WS_VISIBLE | WS_CHILD,
				20, stepPosition1, 360, 24,
				hWnd, (HMENU) NULL, NULL, NULL
			);
			HWND hStepMeta1 = CreateWindow(TEXT("STATIC"), TEXT("Choise the file you want to process with"),
				WS_VISIBLE | WS_CHILD,
				20, stepPosition1+16, 360, 24,
				hWnd, (HMENU) NULL, NULL, NULL
			);

			HWND hOpenFileButton = CreateWindow(TEXT("button"), TEXT("Open file"),
				WS_VISIBLE | WS_CHILD | BS_FLAT,
				20, stepPosition1 + 35, 95, 25,
				hWnd, (HMENU) OPEN_FILE_BUTTON, NULL, NULL,
			);

			hFilename = CreateWindow(TEXT("STATIC"), TEXT("File not selected"),
				WS_VISIBLE | WS_CHILD,
				120, stepPosition1 + 39, 250, 16,
				hWnd, (HMENU) NULL, NULL, NULL
			);

			// Step 2: set password
			int stepPosition2 = stepPosition1 + 80;
			HWND hStep2 = CreateWindow(TEXT("STATIC"), TEXT("Step 2: Set password"),
				WS_VISIBLE | WS_CHILD,
				20, stepPosition2, 360, 24,
				hWnd, (HMENU)NULL, NULL, NULL
			);
			HWND hStepMeta2 = CreateWindow(TEXT("STATIC"), TEXT("Specify a password for the file if necessary"),
				WS_VISIBLE | WS_CHILD,
				20, stepPosition2 + 16, 360, 24,
				hWnd, (HMENU)NULL, NULL, NULL
			);

			hPassword = CreateWindow(TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL | ES_WANTRETURN ,
				20, stepPosition2 + 35, 195, 25,
				hWnd, NULL, hInst, NULL
			);

			// Step 3: Actions
			int stepPosition3 = stepPosition2 + 80;
			HWND hStep3 = CreateWindow(TEXT("STATIC"), TEXT("Step 3: Process file"),
				WS_VISIBLE | WS_CHILD,
				20, stepPosition3, 360, 24,
				hWnd, (HMENU)NULL, NULL, NULL
			);
			HWND hStepMeta3 = CreateWindow(TEXT("STATIC"), TEXT("Choose what you want to do with the file"),
				WS_VISIBLE | WS_CHILD,
				20, stepPosition3 + 16, 360, 24,
				hWnd, (HMENU)NULL, NULL, NULL
			);

			HWND hEncryptButton = CreateWindow(TEXT("button"), TEXT("Encrypt"),
				WS_VISIBLE | WS_CHILD | BS_FLAT,
				20, stepPosition3 + 35, 95, 25,
				hWnd, (HMENU) ENCRYPT_BUTTON, NULL, NULL,
			);

			HWND hDecryptButton = CreateWindow(TEXT("button"), TEXT("Decrypt"),
				WS_VISIBLE | WS_CHILD | BS_FLAT,
				120, stepPosition3 + 35, 95, 25,
				hWnd, (HMENU) DECRYPT_BUTTON, NULL, NULL,
			);

			// About section 
			HWND hAbout = CreateWindow(TEXT("STATIC"), 
				TEXT("NOTE! This program was created for training purposes, so I strongly do not recommend to use it for real-world tasks. If you have any questions, you can contact me via mteru00@gmail.com"),
				WS_VISIBLE | WS_CHILD,
				20, 330, 360, 60,
				hWnd, (HMENU)NULL, NULL, NULL
			);

			hStatusLabel = CreateWindow(TEXT("STATIC"),
				TEXT("      Waiting"),
				WS_VISIBLE | WS_CHILD | SS_CENTERIMAGE,
				0, 420, 400, 24,
				hWnd, (HMENU)NULL, NULL, NULL
			);

			// Control buttons
			HWND hExitButton = CreateWindow(TEXT("button"), TEXT("Exit"),
				WS_VISIBLE | WS_CHILD | BS_FLAT, 
				20, 380, 95, 25,
				hWnd, (HMENU) EXIT_BUTTON, NULL, NULL,
			);

			HFONT hTitleFont = CreateFont(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hDescriptionFont = CreateFont(16, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hStepFont = CreateFont(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hStepMetaFont = CreateFont(16, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hAboutFont = CreateFont(14, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hStatusFont = CreateFont(14, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hEditFont = CreateFont(16, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
			HFONT hButtonFont = CreateFont(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");

			SendMessage(hTitle, WM_SETFONT, WPARAM(hTitleFont), TRUE);
			SendMessage(hDescription, WM_SETFONT, WPARAM(hDescriptionFont), TRUE);
			SendMessage(hStep1, WM_SETFONT, WPARAM(hStepFont), TRUE);
			SendMessage(hStep2, WM_SETFONT, WPARAM(hStepFont), TRUE);
			SendMessage(hStep3, WM_SETFONT, WPARAM(hStepFont), TRUE);
			SendMessage(hStepMeta1, WM_SETFONT, WPARAM(hStepMetaFont), TRUE);
			SendMessage(hStepMeta2, WM_SETFONT, WPARAM(hStepMetaFont), TRUE);
			SendMessage(hStepMeta3, WM_SETFONT, WPARAM(hStepMetaFont), TRUE);
			SendMessage(hFilename, WM_SETFONT, WPARAM(hStepMetaFont), TRUE);
			SendMessage(hAbout, WM_SETFONT, WPARAM(hAboutFont), TRUE);
			SendMessage(hStatusLabel, WM_SETFONT, WPARAM(hStatusFont), TRUE);
			SendMessage(hPassword, WM_SETFONT, WPARAM(hEditFont), TRUE);
			SendMessage(hEncryptButton, WM_SETFONT, WPARAM(hButtonFont), TRUE);
			SendMessage(hDecryptButton, WM_SETFONT, WPARAM(hButtonFont), TRUE);
			SendMessage(hExitButton, WM_SETFONT, WPARAM(hButtonFont), TRUE);
			SendMessage(hOpenFileButton, WM_SETFONT, WPARAM(hButtonFont), TRUE);
		}
		break;
	case WM_CTLCOLORSTATIC:
		{
			static HBRUSH hBrush = CreateSolidBrush(RGB(41, 128, 185));

			if (hStatusLabel == (HWND)lParam)
			{
				HDC hdcStatic = (HDC)wParam;
				SetTextColor(hdcStatic, RGB(255, 255, 255));
				SetBkColor(hdcStatic, RGB(41, 128, 185));
				return (INT_PTR)hBrush;
			}
			HDC hdcEdit = (HDC)wParam;
			SetTextColor(hdcEdit, RGB(44, 62, 80));
			return (LRESULT)GetCurrentObject(hdcEdit, OBJ_BRUSH);
		}
		break;
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);

			int result = -1;
            switch (wmId)
            {
			case OPEN_FILE_BUTTON:
				ofn = { 0 };

				ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = NULL;
				ofn.lpstrFile = szFile;
				ofn.lpstrFile[0] = '\0';
				ofn.nMaxFile = sizeof(szFile);
				ofn.lpstrFilter = L"All\0*.*\0Text\0*.TXT\0";
				ofn.nFilterIndex = 1;
				ofn.lpstrFileTitle = NULL;
				ofn.nMaxFileTitle = 0;
				ofn.lpstrInitialDir = NULL;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

				if (GetOpenFileName(&ofn)) {
					SetWindowText(hFilename, ofn.lpstrFile);
				}
				else {
					SetWindowText(hFilename, L"File not selected");
				}

				break;
			case ENCRYPT_BUTTON:
				ofnSave = { 0 };

				ZeroMemory(&ofnSave, sizeof(ofnSave));
				ofnSave.lStructSize = sizeof(ofn);
				ofnSave.hwndOwner = NULL;
				ofnSave.lpstrFile = szFileSave;
				ofnSave.lpstrFile[0] = '\0';
				ofnSave.nMaxFile = sizeof(szFileSave);
				ofnSave.lpstrFilter = L"All\0*.*\0Text\0*.TXT\0";
				ofnSave.nFilterIndex = 1;
				ofnSave.lpstrFileTitle = NULL;
				ofnSave.nMaxFileTitle = 0;
				ofnSave.lpstrInitialDir = NULL;
				ofnSave.Flags = OFN_PATHMUSTEXIST;

				if (GetOpenFileName(&ofnSave)) {
					TCHAR pass_encrypt[1024];
					GetWindowText(hPassword, pass_encrypt, 1024);
					result = MyEncryptFile((LPTSTR)szFile, (LPTSTR)szFileSave, (LPTSTR)pass_encrypt);
					setStatusMessage(0, result);
				}
				break;
			case DECRYPT_BUTTON:
				ofnSave = { 0 };

				ZeroMemory(&ofnSave, sizeof(ofnSave));
				ofnSave.lStructSize = sizeof(ofn);
				ofnSave.hwndOwner = NULL;
				ofnSave.lpstrFile = szFileSave;
				ofnSave.lpstrFile[0] = '\0';
				ofnSave.nMaxFile = sizeof(szFileSave);
				ofnSave.lpstrFilter = L"All\0*.*\0Text\0*.TXT\0";
				ofnSave.nFilterIndex = 1;
				ofnSave.lpstrFileTitle = NULL;
				ofnSave.nMaxFileTitle = 0;
				ofnSave.lpstrInitialDir = NULL;
				ofnSave.Flags = OFN_PATHMUSTEXIST;

				if (GetOpenFileName(&ofnSave)) {
					TCHAR pass_decrypt[1024];
					GetWindowText(hPassword, pass_decrypt, 1024);
					result = MyDecryptFile((LPTSTR)szFile, (LPTSTR)szFileSave, (LPTSTR)pass_decrypt);
					setStatusMessage(1, result);
				}
				break;
			case EXIT_BUTTON:
				DestroyWindow(hWnd);
				break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}
