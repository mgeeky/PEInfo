
// --------------------------- WinMain -----------------------------------------------
/* Name: 		PEInfo	
 * Date: 		15-07-09 20:00
 * Description: PEInfo is simply semi-raw PE Headers viewer / dumper (and modifier).
 *
////////////////////////		 I N C L U D E S 		//////////////////////////////////// */

#include <windows.h>
#include <iostream>
#include <string>
#include <winnt.h>
#include <commdlg.h>
#include <cctype>
#include <process.h>
#include <ctime>
#include <cmath>
#include <wincrypt.h>		// Hashes

#include "resource.h"

//#pragma data_seg( "PEInfoD")
//#pragma code_seg( "PEInfoC")

#pragma warning(disable: 4996)		// [...] This function [...] may be unsafe. Consider using XXX_s instead	
#pragma warning(disable: 4800)		// 'DWORD': Forcing value to bool 'true' or 'false'
#pragma warning(disable: 4309)		// 'initializing': truncation of constant value

// This constant will tell when to convert RVA to Offset
// and when to not do it (and use RVA as Offset).
// Used in List_IAT and List_EAT.
#define USING_RVA	1

#define IMAGE_SIZEOF_IMPORT_DESCRIPTOR 20
#define IMAGE_SIZEOF_THUNK_DATA 4
#define IMAGE_SIZEOF_IMPORT_BY_NAME 3
#define IMAGE_SIZEOF_DOS_HEADER 64
#define IMAGE_SIZEOF_DOS_STUB 64
#define IMAGE_SIZEOF_OPTIONAL_HEADER 224
#define IMAGE_SIZEOF_SECTION_HEADER 40
#define IMAGE_SIZEOF_EXPORT_DIRECTORY 40

using namespace std;


/* /////////////////////// F U N C T I O N S  D E C L A R A T I O N S ////////////////////// */

BOOL CALLBACK	 	MainWindowProcedure (HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK		EditValueDialogProcedure ( HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK		DumpCertificateProc (HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);

BOOL				CollectInformations (LPSTR szFilePath );

VOID				__Error(char szInfo[], DWORD dwErrno, DWORD dwLine, char szFunction[] );
	#define				Error(x) __Error(x, GetLastError(), __LINE__, __FUNCTION__ )

BOOL				ReadBytes( HANDLE hFile, LPVOID lpBuffer, DWORD dwBufferSize );
BOOL				WriteBytes( HANDLE hFile, LPCVOID lpBuffer, const DWORD dwBufferSize );
UINT WINAPI			DumpPEInfoToDlg( void* lParam );
UINT WINAPI			ComputeLogMakingTime( void* lParam );
char				HexChar(int c);
VOID				FillSecondCombo(DWORD dwSelected);
VOID				OnCommand_EditValueDialog(WPARAM, LPARAM);
BOOL				SaveHeadersToFile();
DWORD				List_IAT(char *, int iSize);
DWORD				List_EAT(char *szLog, int iBufSize);

DWORD				_RVAToOffset ( const DWORD pFileMap, /* const */ DWORD dwRVA );
	#define				RVAToOffset(x,y)	_RVAToOffset((DWORD)x, y)
	#define				RVA2RAW( dwRVA)		_RVAToOffset( (DWORD)g_lpFileMappedOffset, dwRVA);

BOOL				SaveLogToFile();
VOID				AnalyseFile( LPSTR);
BOOL				DoesDataHavePath( LPSTR lpData);
DWORD				DumpDEBUGInfo( LPSTR lpData);
DWORD				DumpCertificateInfo( LPSTR lpData);
void				DumpDelayLoadIAT ( LPSTR lpData );

VOID				Dump(	LPBYTE _lpAddressOfData, long long llSize, LPSTR szBuffer, 
							DWORD dwRelativeOffset = 0, BOOL bWideMode = FALSE, SHORT sTabulators = 0 );

LONG __stdcall		_UnhandledExceptionFilter( _EXCEPTION_POINTERS *pExceptionInfo );


/* ////////////////////////// G L O B A L  V A R I A B L E S /////////////////////////////// */
		
HWND		g_hMain, g_hEditValueDialog, g_hDumpCertificateDialog, g_hHexDumpDialog;
HINSTANCE	g_hInstance;

bool		g_bActive = true;
#if _DEBUG
	bool		g_bTopMost = false;
#else
	bool		g_bTopMost = true;
#endif

HANDLE		g_hDumpPEThread = INVALID_HANDLE_VALUE;

char					g_szFilePath[MAX_PATH + 32 + 1];
IMAGE_DOS_HEADER		g_image_dos_header; 
unsigned char			g_DOS_STUB[256];
DWORD					g_dwDOS_STUB_Length;

ULONG					g_ulNT_Signature;
IMAGE_FILE_HEADER		g_image_file_header;
IMAGE_OPTIONAL_HEADER	g_image_optional_header;
IMAGE_SECTION_HEADER	g_image_section_header[8];

DWORD		g_dwCollectingTime		= 0, 
			g_dwPreparingLogTime	= 0, 
			g_dwReadingIATTime		= 0,
			g_dwReadingEATTime		= 0,
			g_dwFileSize[ 2]		= { 0 },
			g_dwFileSizeLow			= 0;

LPVOID		g_lpFileMappedOffset	= 0;
long long	g_llFileSize;

const DWORD	g_dwDumpedPESize		= 131072;		// Size of buffer to log of file (allocation size)
char		*g_szDumpedPE;
RECT		g_rcEdit;

bool		g_bShowCertificateButton = false;		// Specifies wheter to show Certificate button,
													// which allows to run CertificateAnalysing function.


/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* /////////////////////		 W I N M A I N   	 /////////////////////////////////////// */

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nMode)
{
	g_hInstance = hInstance;  

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
	SetUnhandledExceptionFilter( _UnhandledExceptionFilter);

	g_szDumpedPE = (char*)malloc(g_dwDumpedPESize);

	/* Check if while allocating memory occured a memory leak */
	if( ! g_szDumpedPE || GetLastError() || g_dwDumpedPESize < 10 )
	{
		char szError[ 64] = "";
		sprintf_s( szError, sizeof(szError)-1, "Cannot alloc memory for log variable (%d bytes) !", 
					g_dwDumpedPESize );
		Error( szError);
		return 0xFFFF;
	}

	/* Truncating reserved block to zero */
	ZeroMemory(g_szDumpedPE, g_dwDumpedPESize);

	/* ------------------------------------------------------------------------------------- */    
	g_hMain = CreateDialogA( hInstance, (LPCSTR)IDD_DIALOG1, HWND_DESKTOP, MainWindowProcedure);
	SendMessageA(GetDlgItem(g_hMain, IDC_EDIT2), EM_LIMITTEXT, (WPARAM)10, 0);

#if _DEBUG
	SetWindowTextA(g_hMain, "PEInfo v0.6 (DEBUG)");
#endif

	DragAcceptFiles( g_hMain, TRUE);

	RECT rc;
	CheckDlgButton(g_hMain, IDC_CHECK1, g_bTopMost? BST_CHECKED : BST_UNCHECKED);
	GetWindowRect(g_hMain, &rc);
	SetWindowPos(g_hMain, g_bTopMost? HWND_TOPMOST : HWND_NOTOPMOST, rc.left, rc.top, 
					rc.right-rc.left, rc.bottom-rc.top, SWP_SHOWWINDOW);

    /* Make the window visible on the screen */
    ShowWindow ( g_hMain, nMode );
	
	GetWindowRect( GetDlgItem( g_hMain, IDC_EDIT1), &rc);
	POINT pt = { rc.right, rc.bottom }, pt1 = { rc.left, rc.top };
	ScreenToClient( g_hMain, &pt );
	ScreenToClient( g_hMain, &pt1 );

	g_rcEdit.left = pt1.x;
	g_rcEdit.top = pt1.y;
	g_rcEdit.right = pt.x;
	g_rcEdit.bottom = pt.y;

	MoveWindow( GetDlgItem( g_hMain, IDC_EDIT1), pt1.x, pt1.y, pt.x, pt.y, FALSE);

	UpdateWindow ( g_hMain );

	MSG msgMessages;

	if( strlen( lpCmdLine ) > 0)
	{
		strcpy( g_szFilePath, lpCmdLine);
		SendMessage( g_hMain, WM_COMMAND, IDC_BUTTON1, 0);
	}
    
	/* ------------------------------------------------------------------------------------- */
    /* Run the message loop. Loop is of course infinitve. */
    for(;;)
	{
		if( PeekMessage ( &msgMessages, g_hMain, 0, 0, PM_REMOVE ) != FALSE
			&& ! IsDialogMessageA(g_hEditValueDialog, &msgMessages)
			//&& ! IsDialogMessageA(g_hDumpCertificateDialog, &msgMessages)
			//&& ! IsDialogMessageA(g_hHexDumpDialog, &msgMessages)
		){	
    		/* There is an message to dispatch */ 
        	TranslateMessage 	( &msgMessages );
       		DispatchMessage 	( &msgMessages );	
		}	
    } /* for(;;) */

	/* ------------------------------------------------------------------------------------- */
	
	TerminateThread(g_hDumpPEThread, 0);
	CloseHandle(g_hDumpPEThread);
	g_hDumpPEThread = INVALID_HANDLE_VALUE;

	ZeroMemory(g_szDumpedPE, g_dwDumpedPESize);

	/* Freeing resources */
	if(g_szDumpedPE != NULL) free((void*)g_szDumpedPE);
	g_szDumpedPE = NULL;

	if( g_lpFileMappedOffset != 0 ) UnmapViewOfFile( g_lpFileMappedOffset);
	g_lpFileMappedOffset = 0;

    return (int)msgMessages.wParam;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* /////////////////		W I N D O W  P R O C E D U R E			//////////////////////// */

BOOL CALLBACK MainWindowProcedure (HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_COMMAND:
		{
			DWORD dwCtrlID = LOWORD(wParam);

			if(dwCtrlID == IDC_BUTTON1 )							// "..." - browse file button
			{
				static bool bFirstTime = true;
				g_dwPreparingLogTime = GetTickCount();
				char szTmp[MAX_PATH + 32 + 1] = "";

				if( !bFirstTime ) memset( g_szFilePath, 0, sizeof g_szFilePath );
				else bFirstTime = false;

				if( strlen( g_szFilePath ) == 0)
				{
					OPENFILENAMEA ofn;
					ZeroMemory(&ofn, sizeof(ofn) );
					char *szTitle = "Select valid PE file to run image analysis.";

					ofn.lStructSize	= sizeof( OPENFILENAMEA);
					ofn.Flags		= OFN_FILEMUSTEXIST | OFN_NONETWORKBUTTON | OFN_LONGNAMES | OFN_PATHMUSTEXIST;
					ofn.hInstance	= g_hInstance;
					ofn.hwndOwner	= hDlg;
					ofn.lpstrTitle = szTitle;
					ofn.lpstrFilter	=	"All Valid PE Files (*.exe;*.dll;*.obj;*.lib;*.com)\0*.exe;*.dll;*.obj;*.lib;*.com\0"
										"PE Executables (*.exe)\0*.exe\0PE Dynamic Link Libraries (*.dll)\0*.dll\0"
							#ifdef _DEBUG
										"Semi-PE Object Files (*.obj)\0*.obj\0PE Static Libraries (*.lib)\0*.lib\0"
										"Old DOS Executables (*.com)\0*.com\0"
							#endif
										"All Files (*.*)\0*.*\0";
					ofn.lpstrDefExt	= "exe";
					ofn.nFileOffset = 0;
					ofn.nMaxFile	= MAX_PATH + 32;
					ofn.lpstrFile	= szTmp;

					if(!GetOpenFileNameA(&ofn) || CommDlgExtendedError() || GetLastError() )
					{
						char szError[64] = "";
						sprintf_s(szError, sizeof(szError)-1, "Error while typing file. GetOpenFileNameA failed. (%s() )",
								(GetLastError()? "GLE" : "CDEE"));
						__Error(szError, ((CommDlgExtendedError() )? CommDlgExtendedError() : GetLastError() ), 
								__LINE__, __FUNCTION__);
						break;	
					}

				}else strcpy( szTmp, g_szFilePath);

				AnalyseFile( szTmp );

			}else if( dwCtrlID == IDOK) SendMessageA( hDlg, WM_CLOSE, 0, 0);
			else if( dwCtrlID == IDC_CHECK1 )					// "Stay on top" checkbox
			{
				g_bTopMost = !g_bTopMost;
				CheckDlgButton(hDlg, IDC_CHECK1, (!g_bTopMost)? BST_UNCHECKED : BST_CHECKED );
				RECT rc;
				GetWindowRect(hDlg, &rc);
				SetWindowPos(hDlg, (!g_bTopMost)? HWND_NOTOPMOST : HWND_TOPMOST, 
								rc.left, rc.top, rc.right-rc.left, rc.bottom-rc.top, SWP_SHOWWINDOW);
			}else if( dwCtrlID == IDC_BUTTON2)					// "About" button
			{
				char szAbout[128+1] = "";
				sprintf_s(szAbout, sizeof(szAbout)-1, 
					"PEInfo v0.6, coded by MGeeky #2009\r\nLicense: GPL\r\n\r\n"
					"Any informations or questions send to MGeeky@gmail.com");

				MessageBoxA(NULL, szAbout, "About PEInfo...", MB_ICONINFORMATION);

			}else if(dwCtrlID == IDC_CHECK2)					// "Additional" checkbox
			{
				static BOOL bVisible = FALSE;

				ShowWindow(GetDlgItem(hDlg, IDC_EDIT2),		bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON3),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON4),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON5),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON6),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON7),	bVisible? SW_HIDE : SW_SHOW);

				if( g_bShowCertificateButton == true )
					ShowWindow(GetDlgItem(hDlg, IDC_BUTTON8), bVisible? SW_HIDE : SW_SHOW);

				unsigned uBottom = g_rcEdit.bottom;
				if( !bVisible )	uBottom -= 26;

				MoveWindow( GetDlgItem( g_hMain, IDC_EDIT1), g_rcEdit.left, g_rcEdit.top, 
							g_rcEdit.right, uBottom, TRUE);

				bVisible = !bVisible;
			}
			else if( dwCtrlID == IDC_BUTTON3)					// "10-16" button
			{
				char szValue[16] = "";
				long lValue;
				GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
				if( strlen( szValue) < 1) break;

				lValue = atol(szValue);
				sprintf_s(szValue, sizeof(szValue)-1, "%X", lValue);

				SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

			}else if( dwCtrlID == IDC_BUTTON4)					// "16-10" button
			{
				char szValue[16] = "";
				long lValue;
				GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
				if( strlen( szValue) < 1) break;

				lValue = strtol(szValue, NULL, 16);
				sprintf_s(szValue, sizeof(szValue)-1, "%d", lValue);

				SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

			}else if( dwCtrlID == IDC_BUTTON5 )					// "Edit header" button
			{
				DialogBoxA(g_hInstance, (LPCSTR)IDD_DIALOG2, 
							hDlg, EditValueDialogProcedure);

				ShowWindow(g_hEditValueDialog, SW_SHOW);

			}else if( dwCtrlID == IDC_BUTTON8 )					// "Certificate" button
			{
				DialogBoxParamA(g_hInstance, (LPCSTR)IDD_DIALOG3, 
								hDlg, DumpCertificateProc, 0);

				ShowWindow(g_hDumpCertificateDialog, SW_SHOW);

			}else if( dwCtrlID == IDC_BUTTON9)					// "Hex Dump" button
			{
				/*g_hHexDumpDialog = */DialogBoxParamA(g_hInstance, (LPCSTR)IDD_DIALOG3, 
												hDlg, DumpCertificateProc, 0xC0D3);

				ShowWindow(g_hHexDumpDialog, SW_SHOW);
				UpdateWindow( g_hHexDumpDialog);

			}else if( dwCtrlID == IDC_BUTTON6 )					// "RVA2RAW" button
			{
				char szValue[16] = "";				
				long lValue;
				static bool bDisplayed = false;

				GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);

				lValue = strtol(szValue, NULL, 16);
				if( lValue == LONG(g_lpFileMappedOffset)) break;
				
				sprintf_s(szValue, sizeof(szValue)-1, "%X", RVAToOffset(g_lpFileMappedOffset, lValue));
				SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

			}else if( dwCtrlID == IDC_BUTTON7)					// "Save log" button
				if( strlen(g_szDumpedPE) > 10 && strlen( g_szFilePath) > 2) 
					if( !SaveLogToFile() )
					{
						//MessageBoxA(NULL, "Saving log to file failed !", "Failed while creating log file", MB_ICONERROR);
					}


		}break;

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_DROPFILES:
		{
			char szTmp[MAX_PATH+1] = "";
			HDROP hDrop = (HDROP)wParam;
			DragQueryFileA(hDrop, 0, g_szFilePath, MAX_PATH);
			DragFinish(hDrop);

			sprintf_s(szTmp, sizeof(szTmp)-1, "PEInfo v0.6 - \"%s\"", g_szFilePath);
			
			SetWindowTextA(hDlg, szTmp);
			SetWindowTextA(GetDlgItem(hDlg, IDC_FILEPATH), g_szFilePath);

			CollectInformations( g_szFilePath);

		}break;

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_KEYDOWN:
		{
			if ( LOWORD ( wParam ) == VK_ESCAPE ) SendMessageA ( hDlg, WM_CLOSE, 0, 0 );
		}break;		
					
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_ACTIVATE:
		{	g_bActive = ( (LOWORD(wParam) == WA_ACTIVE)? true : false );
				
		}break;
		
		
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_CLOSE:
		{	
			TerminateThread(g_hDumpPEThread, 0);
			CloseHandle(g_hDumpPEThread);
			g_hDumpPEThread = INVALID_HANDLE_VALUE;

			ZeroMemory(g_szDumpedPE, g_dwDumpedPESize);

			/* Freeing resources */
			if(g_szDumpedPE != NULL) free((void*)g_szDumpedPE);
			g_szDumpedPE = NULL;

			if( g_lpFileMappedOffset != 0 ) UnmapViewOfFile( g_lpFileMappedOffset);
			g_lpFileMappedOffset = 0;

			EndDialog ( hDlg, 0 );
    		ExitProcess(0);
		}break;
		
		
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=- */
		default:
            return FALSE;
            
            
    } /* switch (msg) */

    return TRUE;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////////////////// */

BOOL CALLBACK EditValueDialogProcedure (HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_INITDIALOG:
			g_hEditValueDialog = hDlg;
			CheckRadioButton(hDlg, IDC_RADIO1, IDC_RADIO3, IDC_RADIO3);
			FillSecondCombo(2);
			break;

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_COMMAND:
		{
			if( LOWORD(wParam) == IDC_RADIO1 || LOWORD(wParam) == IDC_RADIO2 
				|| LOWORD(wParam) == IDC_RADIO3)
			{
				switch( LOWORD(wParam) )
				{
				case IDC_RADIO1:
					CheckRadioButton(hDlg, IDC_RADIO1, IDC_RADIO3, IDC_RADIO1);
					FillSecondCombo(0);
					break;
				case IDC_RADIO2:
					CheckRadioButton(hDlg, IDC_RADIO1, IDC_RADIO3, IDC_RADIO2);
					FillSecondCombo(1);
					break;
				case IDC_RADIO3:
					CheckRadioButton(hDlg, IDC_RADIO1, IDC_RADIO3, IDC_RADIO3);
					FillSecondCombo(2);
					break;
				}

			}else if(LOWORD(wParam) == IDCANCEL) SendMessageA(hDlg, WM_CLOSE, 0, 0);
			else OnCommand_EditValueDialog(wParam, lParam);
		}break;

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_KEYDOWN:
		{
			if ( LOWORD ( wParam ) == VK_ESCAPE ) SendMessageA ( hDlg, WM_CLOSE, 0, 0 );
			
		}break;		

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_CLOSE:
		{	
			ShowWindow(g_hMain, SW_SHOW);
			EndDialog ( hDlg, 0 );
			hDlg = 0;
			g_hEditValueDialog = 0;
		}break;
		
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=- */
		default:
            return FALSE;
            
            
    } /* switch (msg) */

    return TRUE;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////////////////// */

#define STANDARD_DUMP_QUANITY 65536/4

BOOL CALLBACK DumpCertificateProc (HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	bool bIsHexDumpDialog = /*(hDlg == g_hHexDumpDialog)? true : false;*/ TRUE;

	unsigned long	cuStandardDumpQuanity = STANDARD_DUMP_QUANITY;
	if( cuStandardDumpQuanity > g_llFileSize ) cuStandardDumpQuanity = (long)g_llFileSize;

    switch (msg)
    {
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_INITDIALOG:
		{
			if( lParam == (LPARAM)0xC0D3 )
			{
				bIsHexDumpDialog = true;
			}else if( lParam == (LPARAM)0 )
			{
				g_hDumpCertificateDialog = hDlg;
				bIsHexDumpDialog = false;
			}

			if( bIsHexDumpDialog == false )				// User has pressed "Certificate" button
			{
				const int ciBufferSize = g_image_optional_header.DataDirectory[4].Size * 6 + 1;
				LPSTR lpDumpData = (LPSTR)malloc( ciBufferSize );
				memset( lpDumpData, 0, ciBufferSize);

				SetWindowTextA( hDlg,	"Dump of Certificate Table entry "
										"( PE.OptionalHeader.DataDirectory[4] ) ");

				DumpCertificateInfo( lpDumpData );

				SetDlgItemTextA( hDlg, IDC_EDIT1, lpDumpData);
				free( (void*)lpDumpData);
				lpDumpData = NULL;
			}
			else if( bIsHexDumpDialog)				// User has pressed "Hex Dump" button
			{											
				ShowWindow( GetDlgItem( hDlg, IDC_OFFSET), SW_SHOW);
				ShowWindow( GetDlgItem( hDlg, IDC_GO), SW_SHOW);
				ShowWindow( GetDlgItem( hDlg, IDC_HEXDEC), SW_SHOW);
				ShowWindow( GetDlgItem( hDlg, IDC_DECHEX), SW_SHOW);
				ShowWindow( GetDlgItem( hDlg, IDC_EDIT2), SW_SHOW);
				ShowWindow( GetDlgItem( hDlg, IDC_RVA2RAW), SW_SHOW);

				SendMessageA(GetDlgItem(g_hMain, IDC_EDIT2), EM_LIMITTEXT, (WPARAM)10, 0);

				char szTitle[ 84] = "";
				DWORD dwTmp = (DWORD)g_llFileSize;
				sprintf(	szTitle, "HEX Dump of file    -    File size:    %ld", g_llFileSize );

				SetWindowTextA( hDlg, szTitle);

				SendDlgItemMessageA( hDlg, IDC_OFFSET, EM_LIMITTEXT, (WPARAM)8, 0);
				SetDlgItemTextA( hDlg, IDC_OFFSET, "0000" );

				SetDlgItemTextA( hDlg, IDC_EDIT1, 
								"\r\n\r\n\t\tPerforming full dump of file. Thread is working...");
				UpdateWindow( hDlg);

				// Preparing dump
				{
					LPVOID lpMemoryBlock = VirtualAlloc( 0, SIZE_T(cuStandardDumpQuanity * 12), 
														MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
					if( lpMemoryBlock == NULL )
					{
						Error( "Cannot allocate virtual memory for full hex dump of file !");
						DumpCertificateProc( hDlg, WM_CLOSE, 0, 0);
						return TRUE;
					}

					Dump( LPBYTE(	g_lpFileMappedOffset), cuStandardDumpQuanity, (LPSTR)
									lpMemoryBlock, 0, 1);
					SetDlgItemTextA( hDlg, IDC_EDIT1, (LPCSTR)lpMemoryBlock);

					VirtualFree(	lpMemoryBlock, SIZE_T(cuStandardDumpQuanity * 12), 
									MEM_DECOMMIT|MEM_RELEASE);
				}
				UpdateWindow( hDlg);
			}		
		}break;

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_COMMAND:
		{
			if( LOWORD(wParam) == IDOK)
				SendMessage( hDlg, WM_CLOSE, 0, 0);

			if( bIsHexDumpDialog) 
			{
				if( LOWORD( wParam) == IDC_GO) 
				{
					char szOffset[ 16] = "";
					bool bIsHex = false;
					GetDlgItemTextA( hDlg, IDC_OFFSET, szOffset, sizeof szOffset - 1 );

					for( unsigned i = 0; i < strlen( szOffset); i++)
						if( isalpha(szOffset[ i] ) )
							if( tolower( szOffset[ i] ) > 'f' )
							{
								MessageBeep( MB_ICONERROR);
								return TRUE;
							}else bIsHex = true;

					unsigned long	lOffset = 0;
					lOffset = atol( szOffset);

					if( lOffset > g_llFileSize )
					{
						char szErr[ 32] = "";
						sprintf( szErr, "You have input invalid offset. Maximum offset in file to reach"
										" is %d (%X).", g_llFileSize, g_llFileSize);
						MessageBoxA(NULL, szErr, "Invalid offset", MB_ICONWARNING);
						break;
					}

					LPVOID lpMemoryBlock = VirtualAlloc( 0, (SIZE_T)cuStandardDumpQuanity * 12, 
														MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
					if( lpMemoryBlock == NULL)
					{
						Error( "Cannot allocate virtual memory for selective dump block!");
						return TRUE;
					}

					SetDlgItemTextA( hDlg, IDC_EDIT1, "\r\n\r\n\t\tPerforming full dump of file...");

					DWORD dwRelative = lOffset - cuStandardDumpQuanity / 2;
					DWORD dwLinesDown = cuStandardDumpQuanity / 32 + 3;

					if( g_llFileSize < STANDARD_DUMP_QUANITY
					||  lOffset < cuStandardDumpQuanity / 2 || dwRelative < 0) {
						dwRelative = 0;
						dwLinesDown = (lOffset/16)+3;
					}

					Dump( (LPBYTE)( DWORD( g_lpFileMappedOffset) + dwRelative ),
							(__int64)cuStandardDumpQuanity, (LPSTR)lpMemoryBlock, 
							dwRelative, true);

					SetDlgItemTextA( hDlg, IDC_EDIT1, (LPCSTR)lpMemoryBlock);
					SendMessageA( GetDlgItem( hDlg, IDC_EDIT1), EM_LINESCROLL, 0, dwLinesDown);

					VirtualFree( lpMemoryBlock, (SIZE_T)cuStandardDumpQuanity * 12, 
								MEM_DECOMMIT|MEM_RELEASE);
					MessageBeep( MB_OK);
				}
				else if( LOWORD(wParam) == IDC_DECHEX)					// "10-16" button
				{
					char szValue[16] = "";
					long lValue;
					GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
					if( strlen( szValue) < 1) break;

					lValue = atol(szValue);
					sprintf_s(szValue, sizeof(szValue)-1, "%X", lValue);

					SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

				}else if( LOWORD(wParam) == IDC_HEXDEC)					// "16-10" button
				{
					char szValue[16] = "";
					long lValue;
					GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
					if( strlen( szValue) < 1) break;

					lValue = strtol(szValue, NULL, 16);
					sprintf_s(szValue, sizeof(szValue)-1, "%d", lValue);

					SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

				}else if( LOWORD(wParam) == IDC_RVA2RAW)
				{
					char szValue[16] = "";				
					long lValue;
					static bool bDisplayed = false;

					GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);

					lValue = strtol(szValue, NULL, 16);
					if( lValue == LONG(g_lpFileMappedOffset)) break;
					
					sprintf_s(szValue, sizeof(szValue)-1, "%X", RVAToOffset(g_lpFileMappedOffset, lValue));
					SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

				}
			}
		}break;

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_KEYDOWN:
		{
			if ( LOWORD ( wParam ) == VK_ESCAPE ) SendMessageA ( hDlg, WM_CLOSE, 0, 0 );
		}break;		

		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_CLOSE:
		{	
			ShowWindow(g_hMain, SW_SHOW);
			EndDialog ( hDlg, 0 );
		}break;
		
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=- */
		default:
            return FALSE; 
            
    } /* switch (msg) */

    return TRUE;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* /////////////////		F U N C T I O N S  D E F I N I T I O N S		//////////////// */

// This procedure prepares log about application error

VOID __Error(char szInfo[], DWORD dwErrno, DWORD dwLine, char szFunction[] )
{

	DWORD dwRes;

	if( dwErrno == 0) return;

	char *szError = (char*)malloc(512);
	
#ifndef _DEBUG
	LPSTR lpMsgBuf = NULL;

	FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, dwErrno, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)lpMsgBuf, 0, NULL );


	sprintf_s(szError,	511, "Application has caught an unhandled exception.\r\n\r\n"
						"Error: %s (%d)\r\n"
						"\r\nIf you want to read detailed information press NO.\r\n"
						"If you want to Terminate application press YES.\r\n"
						"Or if you can ignore this error by click CANCEL button",
						lpMsgBuf, dwErrno);

	dwRes = MessageBoxA(NULL, szError, "PEInfo Error", 
						MB_ICONERROR|MB_APPLMODAL|MB_TASKMODAL|MB_YESNOCANCEL|MB_DEFBUTTON3);
	if( dwRes == IDCANCEL) return;
	else if ( dwRes == IDYES ) goto TERMINATE;
#endif

	sprintf_s(szError, 511, "FATAL ERROR caught. \r\n\r\n"
		"Error code:\t%d\r\nAt line:\t\t%d\r\nIn function:\t%s()\r\nError:\t\t%s\r\n\r\n\r\n"
					 "[?] Do You want to terminate application?", dwErrno, dwLine, szFunction, szInfo);
	
	dwRes = MessageBoxA(NULL, szError, "PEInfo Error", 
					MB_ICONERROR|MB_APPLMODAL|MB_TASKMODAL|MB_YESNO|MB_DEFBUTTON2);

	if( dwRes == IDYES)
	{
TERMINATE:
		ShowWindow( g_hMain, SW_HIDE);

		TerminateThread(g_hDumpPEThread, 0);
		CloseHandle(g_hDumpPEThread);
		g_hDumpPEThread = INVALID_HANDLE_VALUE;

		ZeroMemory(g_szDumpedPE, g_dwDumpedPESize);

		/* Freeing resources */
		if(g_szDumpedPE != NULL) free((void*)g_szDumpedPE);
		g_szDumpedPE = NULL;

		if( g_lpFileMappedOffset != 0 ) UnmapViewOfFile( g_lpFileMappedOffset);
		g_lpFileMappedOffset = 0;

		EndDialog ( g_hMain, 0 );
		ExitProcess(0);
	}

	free((void*)szError);
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// Function loads file, and read from it PE Headers.

BOOL CollectInformations (LPSTR szFilePath )
{

	/* -------------------------- Variables ------ */
	DWORD dwBytes = 0;
	DWORD nOffset;
	
	ULONG ul_NT_Signature = 0;

	HANDLE hFile;

	IMAGE_DOS_HEADER image_dos_header;
	IMAGE_FILE_HEADER image_file_header;
	IMAGE_OPTIONAL_HEADER32 image_optional_header;
	IMAGE_SECTION_HEADER image_section_header;

	ZeroMemory(&g_image_dos_header, IMAGE_SIZEOF_DOS_HEADER );
	ZeroMemory(&g_image_file_header,IMAGE_SIZEOF_FILE_HEADER);
	ZeroMemory(&g_image_optional_header, IMAGE_SIZEOF_OPTIONAL_HEADER);
	ZeroMemory(g_image_section_header, IMAGE_SIZEOF_SECTION_HEADER * 8);
	ZeroMemory(&g_ulNT_Signature, sizeof(g_ulNT_Signature) );
	ZeroMemory(&g_DOS_STUB, sizeof(g_DOS_STUB) );

	/* -------------------------- Variables ------ */

	/* Open the file */
	hFile = CreateFileA(szFilePath, GENERIC_READ, 
						FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
						OPEN_EXISTING, 0, NULL );
	if( hFile == INVALID_HANDLE_VALUE || GetLastError() )
	{
		char szTmp[60] = "";
		sprintf_s(szTmp, sizeof(szTmp)-1, "Cannot open file (\"%s\") !", szFilePath);
		Error( szTmp);
		return FALSE;
	}

	// Getting size of file
	DWORD	dwFileSizeLow = 0, dwFileSizeHigh = 0;
	dwFileSizeLow = GetFileSize( hFile, &dwFileSizeHigh);

	g_llFileSize = dwFileSizeLow + dwFileSizeHigh;
	g_dwFileSizeLow = dwFileSizeLow;

	/* Read IMAGE_DOS_HEADER */
	ReadBytes(hFile, (LPVOID)&image_dos_header, sizeof(IMAGE_DOS_HEADER) );
	if( (IMAGE_DOS_SIGNATURE != image_dos_header.e_magic && image_dos_header.e_magic != 'ZM') || GetLastError()  )
	{
		if( isalnum((image_dos_header.e_cblp & 0xFF)) == TRUE)
			Error( "This format of application file is not supported by PEInfo (format is too old).");
		else Error( "This is not valid application file. It cannot be parsed by PEInfo.");

		CloseHandle( hFile);
		return FALSE;
	}

	// Retrieving DOS STUB
	{
		FILE *pFile;
		pFile = fopen(g_szFilePath, "r");
		if( pFile != NULL)
		{
			char c = 0;
			DWORD dwOffset = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);

			fseek(pFile, dwOffset, SEEK_SET);

			for( unsigned i = 0; i < (image_dos_header.e_lfanew - dwOffset); i++)
			{
				if( i == sizeof(g_DOS_STUB) ) break;

				c = fgetc(pFile);
				
				if( !pFile || GetLastError() ) 
					break;
				
				g_DOS_STUB[i] = c;
				g_dwDOS_STUB_Length = i;
			}
			if( g_dwDOS_STUB_Length > 0)
				g_DOS_STUB[g_dwDOS_STUB_Length+1] = '\0';

			fclose( pFile);
		}
	}
	

	/* Setting file pointer to IMAGE_NT_HEADERS offset in file */
    if ((nOffset = 
		SetFilePointer(hFile, image_dos_header.e_lfanew /* IMAGE_NT_HEADERS */, NULL, FILE_BEGIN)) == 0xFFFFFFFF
		 || GetLastError() )
    {
        Error( "SetFilePointer failed.");
        return FALSE;
	}

	/* Read IMAGE_NT_HEADERS->Signature */
	ReadBytes( hFile, (LPVOID)&ul_NT_Signature, sizeof(ULONG) );
	if( ul_NT_Signature != IMAGE_NT_SIGNATURE || GetLastError()  )
	{
		Error( "There is no valid NT Signature in file. Unknown file type.");
		return FALSE;
	}
	
	/* Read IMAGE_FILE_HEADER */
	ReadBytes( hFile, (LPVOID)&image_file_header, IMAGE_SIZEOF_FILE_HEADER );
	 
	/* Read IMAGE_OPTIONAL_HEADER32 */
	ReadBytes( hFile, (LPVOID)&image_optional_header, sizeof(IMAGE_OPTIONAL_HEADER32) );

	for(int i = 0; i<8; i++)
	{
		ReadBytes( hFile, (LPVOID)&image_section_header, sizeof(image_section_header) );
		if( strlen((const char*)image_section_header.Name) < 1 ) break;

		g_image_section_header[i] = image_section_header;
	}

	/* Close the file */
	CloseHandle( hFile);

	/* Now specific for PEInfo function. It will interprete 
	 * sended infos (from structures), and will print this values
	 * to expected places in info dialogs 
	 */

	strncpy_s(g_szFilePath, sizeof(g_szFilePath)-1, szFilePath, MAX_PATH);
	g_image_dos_header = image_dos_header;
	g_image_file_header = image_file_header;
	g_image_optional_header = image_optional_header;

	if( g_hDumpPEThread != INVALID_HANDLE_VALUE)
	{
		TerminateThread(g_hDumpPEThread, 0);
		WaitForSingleObject(g_hDumpPEThread, 300);
		CloseHandle(g_hDumpPEThread);
		g_hDumpPEThread = INVALID_HANDLE_VALUE;
	}

	if( g_image_optional_header.DataDirectory[4].VirtualAddress != 0
		&& g_image_optional_header.DataDirectory[4].Size != 0 ) g_bShowCertificateButton = true;

	g_hDumpPEThread = (HANDLE)_beginthreadex(NULL, 0, DumpPEInfoToDlg, (LPVOID)GetDlgItem(g_hMain, IDC_EDIT1), 0, NULL);

	return TRUE;
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function read bytes from proper file.

BOOL ReadBytes( HANDLE hFile, LPVOID lpBuffer, DWORD dwBufferSize )
{
	DWORD dwBytes = 0;
	static unsigned uReadCounter = 0;

	if( ! ReadFile( hFile, (LPVOID)lpBuffer, dwBufferSize, &dwBytes, NULL) || GetLastError()  )
	{
		Error( "Error while reading file !" );
		return FALSE;
	}
	uReadCounter++;

	if( dwBufferSize != dwBytes || GetLastError()  )
	{
		char szInfo[64] = "";
		sprintf_s(szInfo, sizeof(szInfo), "Read wrong number of bytes ! Expected %lu, got %lu. (at: %X)", 
				dwBufferSize, dwBytes, uReadCounter);
		Error( szInfo);
		return FALSE;
	}
	
	return TRUE;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function write bytes to proper file.

BOOL WriteBytes( HANDLE hFile, LPCVOID lpBuffer, const DWORD dwBufferSize )
{
	DWORD dwBytes = 0, dwTmp;
	static unsigned uWriteCounter = 0;

	if( dwBufferSize > 0x800)
	{
		unsigned uIterates = ( dwBufferSize / 11 ) + 1;


		for(unsigned i = 0; i < uIterates  && dwBytes <= dwBufferSize; i++)
		{

			if( ! WriteFile( hFile, (LPVOID)(DWORD(lpBuffer)+(i<<11)), 2048, &dwTmp, NULL) || GetLastError()  )
			{
				Error( "Error while reading file !" );
				return FALSE;
			}
			uWriteCounter++;

			if( 2048 != dwTmp || GetLastError() && i != uIterates-1 )
			{
				char szInfo[64] = "";
				sprintf_s(szInfo, sizeof(szInfo),	" Written wrong number of bytes ! To write: 2048, written: %lu. (at: %X)\r\n"
													"Writing mode: iteration, all data to write: %d, iteration no. %d/%d\r\n", 
													dwTmp, uWriteCounter, dwBufferSize, i, uIterates-1);
				Error( szInfo);
				return FALSE;
			}

			dwBytes += dwTmp;
		}

	}else
	{
		if( ! WriteFile( hFile, (LPVOID)lpBuffer, dwBufferSize, &dwBytes, NULL) || GetLastError()  )
		{
			Error( "Error while reading file !" );
			return FALSE;
		}
		uWriteCounter++;

		if( dwBufferSize != dwBytes || GetLastError()  )
		{
			char szInfo[64] = "";
			sprintf_s(szInfo, sizeof(szInfo), " Written wrong number of bytes ! To write: %lu, written: %lu. (at: %X)", 
					dwBufferSize, dwBytes, uWriteCounter);
			Error( szInfo);
			return FALSE;
		}
	}
	
	return TRUE;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
// RVAToOffset procedure (converts Relatives to absolute offset), by MGeeky

DWORD _RVAToOffset ( const DWORD pFileMap, DWORD dwRVA )
{
	DWORD dwTmp = 0;
	
	PIMAGE_DOS_HEADER		idh			= (PIMAGE_DOS_HEADER)	pFileMap;
	PIMAGE_NT_HEADERS		inthdr		= (PIMAGE_NT_HEADERS)	DWORD(pFileMap + idh->e_lfanew);
	PIMAGE_FILE_HEADER		ifh			= (PIMAGE_FILE_HEADER)	DWORD( pFileMap + idh->e_lfanew + 4 );
	
	//	Get Offset to Section Headers Table (after IMAGE_OPTIONAL_HEADER)
	DWORD					dwOffset	= (DWORD)(pFileMap + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS) );
	PIMAGE_SECTION_HEADER	ish			= (PIMAGE_SECTION_HEADER)dwOffset;
	
	DWORD dwNumOfSections				= ifh->NumberOfSections;
	
	while( dwNumOfSections > 0)
	{
		if( dwRVA >= ish->VirtualAddress )
		{
			dwTmp = ish->VirtualAddress + ish->SizeOfRawData;
			if( dwRVA < dwTmp ) 
			{	
				// The searched address is in this section
				dwRVA -= ish->VirtualAddress;
				dwTmp = ish->PointerToRawData + dwRVA;
				return dwTmp;
			}
		}
		
		__asm {
			mov eax, [ish];
			add eax, IMAGE_SIZEOF_SECTION_HEADER
			mov [ish], eax
		}

		dwNumOfSections--;
	}

	return dwRVA;
}

/* ///////////////////////////////////////////////////////////////////////////////////////// */

#if USING_RVA != 1 && USING_RVA != 0
	#error USING_RVA must be 0 or 1 ! (declared at 28 line )
#endif

/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function list all IAT (Import Address Table) entries: modules and its exports.

DWORD List_IAT(char *szLog, int iBufSize)
{

	/* -------------------------- Variables -------------------------- */
	PIMAGE_IMPORT_DESCRIPTOR	image_import_descriptor;
	PIMAGE_OPTIONAL_HEADER		ioh;
	PIMAGE_THUNK_DATA			image_thunk_data;
	PIMAGE_IMPORT_BY_NAME		image_import_by_name;

	DWORD		nOffset					= 0,
				dwSizeLow				= 0,
				dwSizeHigh				= 0,
				dwImportedFunctions		= 0,
				
				dwImpSectionVA			= 0, 
				dwImpSectionSize		= 0,
				dwOffset				= 0;

	const		DWORD	dwSizeOfTmp		= 1024;
	char		*szTmp					= (char*)malloc( dwSizeOfTmp);
	char		szName[128]				= "";

	LPVOID		lpBuffer				= g_lpFileMappedOffset;
	time_t		tTimeDateStamp;

	if( szTmp == NULL)
	{
		Error( "Cannot allocate memory for szTmp variable.");
		return ERROR_MEMORY_HARDWARE;
	}

	memset( szTmp, 0, dwSizeOfTmp);

	/* -------------------------- Variables -------------------------- */

	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)g_lpFileMappedOffset;

	dwOffset = (DWORD)g_lpFileMappedOffset + idh->e_lfanew+ 4 + IMAGE_SIZEOF_FILE_HEADER;
	ioh = ((PIMAGE_OPTIONAL_HEADER)( dwOffset));

	// Getting offset to the first IMAGE_IMPORT_DESCRIPTOR structure and size of import table
	dwImpSectionVA = RVAToOffset(lpBuffer, ioh->DataDirectory[1].VirtualAddress);

	dwImpSectionSize = ioh->DataDirectory[1].Size;

	// Iterating all imported modules and its functions
	for( int i = 0; ; i++)
	{
		ZeroMemory(szTmp, dwSizeOfTmp );

		if( strlen( szLog) >= unsigned(iBufSize - 200) || GetLastError()  )
		{
			Error( "Buffer is too small to carry all informations about Import Table !");
			break;
		}

		// Now we taking access to IMAGE_IMPORT_DESCRIPTOR
		dwOffset = DWORD(g_lpFileMappedOffset) + dwImpSectionVA + (i * IMAGE_SIZEOF_IMPORT_DESCRIPTOR );
		image_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)( dwOffset);

		if( image_import_descriptor->OriginalFirstThunk == NULL
			|| image_import_descriptor->FirstThunk == NULL )
			break;

		// Computing offset of a module name
		dwOffset = RVAToOffset(g_lpFileMappedOffset, image_import_descriptor->Name);

		dwOffset += (DWORD)lpBuffer;

		// Preparing name of imported module.
		if( strlen((const char*)dwOffset) > 0)
		{
			strncpy_s(	szName, sizeof(szName)-1, (const char*)dwOffset, strlen((const char*)dwOffset) );
		}else strcpy_s(	szName, sizeof(szName)-1, "Unknown");

		sprintf_s(szTmp, dwSizeOfTmp-1, 
						"\t// ::::::::::::::::::\r\n\r\n\tIMAGE_IMPORT_DESCRIPTOR[%d]\r\n\t{\r\n\t\t"
						"OriginalFirstThunk:\t\t%X;\r\n\t\tTimeDateStamp:\t\t%X;", i, 
						image_import_descriptor->OriginalFirstThunk,  
						image_import_descriptor->TimeDateStamp );

		if( image_import_descriptor->TimeDateStamp > 0 
			&& image_import_descriptor->TimeDateStamp < 0XFFFFFFFF)
		{
			tTimeDateStamp = (time_t)image_import_descriptor->TimeDateStamp;
			sprintf_s( szTmp, dwSizeOfTmp-1, "%s\r\n\t\t\t\t\t( %s )", szTmp, ctime( &tTimeDateStamp) );
		}
						
		sprintf_s(szTmp, dwSizeOfTmp-1, "%s\r\n\t\tForwarderChain:\t\t%X;\r\n\t\tName:\t\t\t\"%s\";\r"
						"\n\t\tFirstThunk:\t\t%X;\r\n\r\n"
						"\t\tOffset of this descriptor:\t%X;\r\n\r\n"
						"\r\n\t\t #.)\tHint/Ord\tAPI Name\r\n"
						"\t\t+--------------------------------------------+\r\n", 
						szTmp, image_import_descriptor->ForwarderChain, szName, 
						image_import_descriptor->FirstThunk,
						( dwImpSectionVA + (i * IMAGE_SIZEOF_IMPORT_DESCRIPTOR ) )
		);

		if(szLog != NULL) strcat_s(szLog, iBufSize-1, szTmp);

		// Iterating all imported functions from this module
		int f = 0;
		while( true )
		{
			if( strlen( szLog) >= unsigned(iBufSize - 60) || GetLastError()  )
			{
				Error( "Buffer is too small to carry all informations about Import Table Entries !");
				free( szTmp);
				return 0xFFFF;
			}

			// Getting access to thunk RVA
			dwOffset = DWORD(g_lpFileMappedOffset) + (f * IMAGE_SIZEOF_THUNK_DATA);
			dwOffset += RVAToOffset(lpBuffer, image_import_descriptor->OriginalFirstThunk);

			image_thunk_data = (PIMAGE_THUNK_DATA)( dwOffset);
			if( image_thunk_data->u1.Function == NULL ) break;
			
			ZeroMemory(szTmp, dwSizeOfTmp );

			DWORD dwIsImportedByValue = ( DWORD(image_thunk_data->u1.Ordinal) & IMAGE_ORDINAL_FLAG32 );
			if( dwIsImportedByValue == 0 )
			{
				// Function imported by Name (because  31th bit is not set )
				ZeroMemory( &image_import_by_name, IMAGE_SIZEOF_IMPORT_BY_NAME );

				dwOffset = ( DWORD(lpBuffer) + RVAToOffset(lpBuffer, image_thunk_data->u1.Function) );
				image_import_by_name = (PIMAGE_IMPORT_BY_NAME)( dwOffset);

				int i = 0, iLastAlnum = 0;
				bool bBreaked = false;
				while( ( image_import_by_name->Name[i] != '\0') && ++i && ++iLastAlnum && !bBreaked )
					if( i >= 60 ) bBreaked = true;
					else if( isprint( image_import_by_name->Name[i]) == FALSE) bBreaked = true;

				if( bBreaked) 
				{
					strncpy_s( szName, sizeof( szName)- 1, (const char*)image_import_by_name->Name, 
							iLastAlnum);
					szName[iLastAlnum+1] = '\0';
				}else strcpy_s( szName, sizeof( szName)- 1, (const char*)image_import_by_name->Name);


				sprintf_s(szTmp, dwSizeOfTmp-1, "\t\t| %d.)\t%04X\t%s\r\n", f, 
							image_import_by_name->Hint, szName  );
			}else
			{
				// Function imported by a Value (31th bit is set )
				sprintf_s(szTmp, dwSizeOfTmp-1, "\t\t| %d.)\t%04X\t(by Ordinal)\r\n", 
					f, IMAGE_ORDINAL_FLAG32 & DWORD(image_thunk_data->u1.Ordinal) );
			}

			if(szLog != NULL) strcat_s( szLog, iBufSize-1, szTmp);		

			++f;

		} // while( true)

		if(szLog != NULL) 
		{
			sprintf_s( szTmp, dwSizeOfTmp -1, 
						"\t\t+--------------------------------------------+\r\n\r\n"
						"\t\tFunctions imported by this module: %d;\r\n\r\n\t}; // Imported"
						" from %d. module\r\n\r\n", f, i);
			strcat_s(szLog, iBufSize-1, szTmp);

			dwImportedFunctions += f;
		}

	} // for( int i = 0; ; i++)

	ZeroMemory(szTmp, dwSizeOfTmp -1);
	sprintf_s(szTmp, dwSizeOfTmp-1, "\r\n\r\n\tAll imported functions by this application:\t%d;", dwImportedFunctions);
	strcat_s(szLog, iBufSize, szTmp);

	free( szTmp);
	return 0;
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function list all EAT (Export Address Table) entries.

DWORD List_EAT(char *szLog, int iBufSize)
{

	/* -------------------------- Variables -------------------------- */
	PIMAGE_EXPORT_DIRECTORY		image_export_directory;
	PIMAGE_OPTIONAL_HEADER		ioh;

	DWORD		nOffset		= 0, dwOffset = 0;
	DWORD		dwSizeLow	= 0,
				dwSizeHigh	= 0;
	
	DWORD		dwExpSectionVA, dwExpSectionSize;
	LPVOID		lpOffset	= 0;
	LPVOID		lpBuffer	= g_lpFileMappedOffset;

	const DWORD	dwSizeOfTmp	= 2048;
	char *szTmp				= (char*)malloc( dwSizeOfTmp);
	char szName[512]		= "";

	if( szTmp == NULL)
	{
		Error( "Cannot allocate memory for szTmp variable");
		return ERROR_MEMORY_HARDWARE;
	}

	memset( szTmp, 0, dwSizeOfTmp);

	/* -------------------------- Variables -------------------------- */

	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)lpBuffer;

	dwOffset = (DWORD)lpBuffer + idh->e_lfanew+ 4 + IMAGE_SIZEOF_FILE_HEADER;
	ioh = ((PIMAGE_OPTIONAL_HEADER)( dwOffset));

	// Getting offset to the first IMAGE_IMPORT_DESCRIPTOR structure and size of import table
	dwExpSectionVA = RVAToOffset(lpBuffer, ioh->DataDirectory[0].VirtualAddress);
	dwExpSectionSize = ioh->DataDirectory[0].Size;

	ZeroMemory(szTmp, dwSizeOfTmp );

	if( strlen( szLog) >= unsigned(iBufSize - 200) || GetLastError()  )
	{
		Error( "Buffer is too small to carry all informations about Export Table !");
		free( szTmp);
		return 0xFFFF;
	}

	// Now we taking access to IMAGE_EXPORT_DIRECTORY
	dwOffset = DWORD(lpBuffer) + dwExpSectionVA;
	image_export_directory = (PIMAGE_EXPORT_DIRECTORY)( dwOffset);

	if( image_export_directory->AddressOfFunctions == NULL &&
		image_export_directory->AddressOfNameOrdinals == NULL &&
		image_export_directory->AddressOfNames == NULL &&
		image_export_directory->Name == NULL){
		free( szTmp);
		return 0xFFFF;
	}

	// Computing offset of a module name 
	dwOffset = RVAToOffset(lpBuffer, image_export_directory->Name);
	dwOffset += (DWORD)lpBuffer;

	// Preparing name of exported module.
	if( dwOffset != NULL && strlen((const char*)dwOffset) > 0)
	{
		strncpy_s(	szName, sizeof(szName)-1, (const char*)dwOffset, strlen((const char*)dwOffset) );
	}else strcpy_s(	szName, sizeof(szName)-1, "Unknown");

	sprintf_s(szTmp, dwSizeOfTmp-1, "\tCharacteristics:\t\t%X;\r\n\tTimeDateStamp:\t\t%X;", 
					image_export_directory->Characteristics, image_export_directory->TimeDateStamp );
					
	if( image_export_directory->TimeDateStamp > 0 
			&& image_export_directory->TimeDateStamp < 0XFFFFFFFF)
	{
		time_t tTimeDateStamp = (time_t)image_export_directory->TimeDateStamp;
		sprintf_s( szTmp, dwSizeOfTmp-1, "%s\r\n\t\t\t\t( %s )", szTmp, ctime( &tTimeDateStamp) );
	}
					
	sprintf_s(szTmp, dwSizeOfTmp-1, "%s\r\n\tMajorVersion:\t\t\t%X;\r\n\tMinorVersion:\t\t\t%X;\r"
					"\n\tName:\t\t\t\"%s\";\r\n\tOrdinalBase:\t\t%X;\r\n\tNumberOfFunctions:\t%X;"
					"\r\n\tNumberOfNames:\t\t%X;\r\n\tAddressOfFunctions:\t%X;\r\n\tAddressOfNames:\t"
					"\t%X;\r\n\tAddressOfNameOrdinals:\t%X;\r\n"
					"\r\n\tOffset of this export directory:\t%X;\r\n\r\n"
					"\r\n\t #.)\tOrdinal\tRVA\tAPI Name\r\n"
					"\t+-----------------------------------------------------------------+\r\n", 
					szTmp, image_export_directory->MajorVersion, image_export_directory->MinorVersion, 
					szName, image_export_directory->Base, image_export_directory->NumberOfFunctions,
					image_export_directory->NumberOfNames, image_export_directory->AddressOfFunctions,
					image_export_directory->AddressOfNames, image_export_directory->AddressOfNameOrdinals,
					dwExpSectionVA
	);

	if(szLog != NULL) strcat_s(szLog, iBufSize-1, szTmp);

	int		f			= 0, iIndex = 0;
	WORD	wOrdinal	= 0;
	DWORD	dwRVA		= 0, 
			dwNameRVA	= 0, dwTmp = 0;
	WORD	*aOrdinals;
	DWORD	*aAddresses, *aNamesRVA;

	dwRVA		= RVAToOffset(lpBuffer, image_export_directory->AddressOfFunctions  );
	aOrdinals	= (WORD *)(DWORD(lpBuffer) + 
					RVAToOffset(lpBuffer, image_export_directory->AddressOfNameOrdinals ));
	aAddresses	= (DWORD*)(DWORD(lpBuffer) + dwRVA);
	aNamesRVA	= (DWORD*)(DWORD(lpBuffer) + RVAToOffset(lpBuffer, image_export_directory->AddressOfNames ));

	// Iterating all exported functions from this module
	for(f = 0; unsigned(f) < image_export_directory->NumberOfFunctions; f++)
	{
		if( strlen( szLog) >= unsigned(iBufSize - 30) || GetLastError()  )
		{
			Error( "Buffer is too small to carry all informations about Export Table Entries !");
			break;
		}

		ZeroMemory(szTmp, dwSizeOfTmp );
		ZeroMemory(szName, sizeof(szName));

		wOrdinal	= aOrdinals[ f];
		dwNameRVA	= RVAToOffset( lpBuffer, aNamesRVA[ f]) + DWORD(lpBuffer);

		iIndex		= wOrdinal - image_export_directory->Base;
		dwRVA		= aAddresses[ iIndex] + DWORD(lpBuffer);
		dwTmp		= *((DWORD*)dwRVA);

		if( (dwNameRVA-dwOffset) > g_dwFileSize[ 0] + g_dwFileSize[ 1] ) break;

		// Parsing name of an export thunk
		if( HexChar( *((char*)dwNameRVA)) == '.' )
		{
			if( wOrdinal != 0 &&  wOrdinal > image_export_directory->Base && 
				wOrdinal <= ( image_export_directory->Base + image_export_directory->NumberOfFunctions ))
				sprintf_s(szName, sizeof(szName)-1, "#%4X (%d.) - by Ordinal", wOrdinal, wOrdinal);
			else strcpy_s(szName, sizeof(szName)-1, "Unknown");
		}
		else strcpy_s(szName, sizeof(szName)-1, (const char*)(dwNameRVA) );

		// Retrieveing address...
		if( dwTmp > g_image_optional_header.SizeOfImage )
		{
			dwTmp = RVAToOffset( lpBuffer, aAddresses[ iIndex]) + DWORD( lpBuffer);
			char c = *((char*)dwTmp);
			char *szTest = (char*)dwTmp;
			unsigned uTmp = strlen( szTest);
			if(c >= '0' && c <= 'z') {
				for( unsigned u = uTmp-1; u > 0; u--)
					if( !( szTest[ u] >= 0x20 && szTest[ u] <= 0x7A) ) goto __NOT_FORWARDED;

				if( strlen( szTest) > 3)		// Function is forwarded...
					sprintf_s( szName, sizeof szName - 1, "%s -> %s", szName, (const char*)dwTmp);
			}
		}
		__NOT_FORWARDED:

		sprintf_s(szTmp, dwSizeOfTmp-1, "\t| %d.)\t%04X\t%08X\t%s\r\n", f, 
				wOrdinal, dwRVA - DWORD(lpBuffer), szName  );

		if(szLog != NULL) strcat_s( szLog, iBufSize-1, szTmp);

	} // for(f = 0; unsigned(f) < image_export_directory->NumberOfFunctions; f++)

	if(szLog != NULL) 
	{
		sprintf_s( szTmp, dwSizeOfTmp -1, 
					"\t+-----------------------------------------------------------------+\r\n\r\n"
					"\tFunctions exported by this module: %d;\r\n\r\n\r\n",
					f);
		strcat_s(szLog, iBufSize-1, szTmp);
	}

	free( szTmp);
	return 0;
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function prepares a log about selected file and prints it.

UINT WINAPI DumpPEInfoToDlg( void* lParam )
{

	// This function prepares and shows log of analyzed file.

	/* ------------------------------- Variables ----------------- */
	HWND hwnd										= (HWND)lParam;

	DWORD dwOffset									= 0;
	const DWORD dwTmpSize							= 2048;
	char szTmp[dwTmpSize]							= "",
		 szTmp2[dwTmpSize]							= "",
		 *szStub									= (char*)malloc(g_dwDOS_STUB_Length*10+2);

	IMAGE_SECTION_HEADER *pImage_section_header		= NULL;
	/* ----------------------------------------------------------- */

	memset( szStub, 0, g_dwDOS_STUB_Length*10+2);


	/* Preparing dump of DOS_STUB - first 16 bytes of.
	 * We will use here mine function HexChar which returns dot char or
	 * char sended as parameter if it's code is in allowed code area
	 */

	Dump( (BYTE*)g_DOS_STUB, g_dwDOS_STUB_Length, szStub);

	DWORD dwSizeLow, dwSizeHigh;
	HANDLE hFile = CreateFileA(	g_szFilePath, GENERIC_READ, FILE_SHARE_READ, 
								NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if( !hFile || GetLastError())
	{
		Error( "Cannot open file to check its size !");
	}else
	{
		dwSizeLow = GetFileSize(hFile, &dwSizeHigh);
	}
	CloseHandle( hFile);

	g_dwFileSize[ 0] = dwSizeLow;
	g_dwFileSize[ 1] = dwSizeHigh;

	time_t tTimeDateStamp = (time_t)g_image_file_header.TimeDateStamp;
	time_t tNowTDS;
	time( &tNowTDS);

	
	ZeroMemory(szTmp2, dwTmpSize);
	ZeroMemory(szTmp, dwTmpSize);

	/* This is next step in describing file.
	 * Here we will try to stretch out a flag, and
	 * if this flag will be present in Characteristics
	 * value, then we prepare proper message.
	 */
	if( g_image_file_header.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- There are no informations about \"relocations\";");
	if( g_image_file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- This is an Executable File (not .OBJ or .LIB);");
	if( g_image_file_header.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- There are no line numbers in file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- Local symbols are not in file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- Application can address more than 2 Gigabytes;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_32BIT_MACHINE) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- For 32 bit machines;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- Informations about symbols are in *.dbg file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- copy and run from SWAP;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- when file is in the net, copy and run from SWAP;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_SYSTEM) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- System file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_DLL) 
		strcat_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t- Dynamic Link Library file;");

	if( strlen(szTmp2 ) == 0) strcpy_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t\t\t[!] There is no valid flags set in Characteristics!");


	/* Recognizing Machine.
	 * Here we will read value from IMAGE_FILE_HEADER->Machine,
	 * and make proper message.
	 */
	char	szTmp3[ 65] = "";

	switch( g_image_file_header.Machine)
	{
	case IMAGE_FILE_MACHINE_ALPHA:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "ALPHA - DEC Alpha architecture");
		break;
	case IMAGE_FILE_MACHINE_I386:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "i386 - 80386 arch. application");
		break;
	case IMAGE_FILE_MACHINE_UNKNOWN:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "UNKNOWN - Unknown machine");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "IA64 - Intel (64bit) arch");
		break;
	case IMAGE_FILE_MACHINE_AXP64:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "AXP64 - Alpha (64bit) / AXP64 arch");
		break;
	case IMAGE_FILE_MACHINE_AM33:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "AM33 - AM33 arch");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "AMD64 - AMD 64bit architecture");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "POWERPC - PowerPC architecture");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "MIPSFPU - MIPS FPU arch");
		break;
	default:
		strcpy_s(szTmp3, sizeof(szTmp3)-1, "Other, not recognized architecture");
		break;
	}

	
	/* Here we read information about application subsystem, 
	 * and then prepares a message 
	 */
	char	szTmp4[ 80] = "";

	switch(g_image_optional_header.Subsystem)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- Unknown Subsystem;");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- No subsystem required (dev. drivers & native syst. procs.);");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- Graphical user interface (GUI);");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- Character-mode/Console user interface (CUI);");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- OS/2 CUI subsystem;");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- Windows CE system;");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- Extensible Firmware Interface (EFI) app.;");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- EFI driver with boot services;");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- EFI driver with run-time services;");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- EFI Rom Image;");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- XBox subsystem file;");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		strcpy_s(szTmp4, sizeof(szTmp4)-1, "\r\n\t\t\t- Boot application (BootLoader);");
		break;
	}


	/* Now, stretching out flags, 
	 * which will tell about file characteristics. 
	 */
	char	szTmp5[ 512] = "";

	if(g_image_file_header.Characteristics & IMAGE_FILE_DLL
		&& g_image_optional_header.DllCharacteristics != 0)
	{
		strcpy( szTmp5, "\r\n\t\t{");

		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) 
			strcat_s(szTmp5, sizeof(szTmp5)-1, "\r\n\t\t\t- The DLL can be relocated at load time;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) 
			strcat_s(szTmp5, sizeof(szTmp5)-1, "\r\n\t\t\t- Code integrity checks are forced;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) 
			strcat_s(szTmp5, sizeof(szTmp5)-1, "\r\n\t\t\t- The image is compatible with Data Execution Prevention");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
		||  g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) 
			strcat_s(szTmp5, sizeof(szTmp5)-1, "\r\n\t\t\t- The image is isolation aware, but shouldn't be isolated");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) 
			strcat_s(szTmp5, sizeof(szTmp5)-1, "\r\n\t\t\t- Do not bind the image;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) 
			strcat_s(szTmp5, sizeof(szTmp5)-1, "\r\n\t\t\t- The image is terminal server aware;");
		
		if( strlen(szTmp5) == 0) strcpy_s(szTmp5, sizeof(szTmp5)-1, 
											"\r\n\t\t\t[!] There aren't valid DLL Characteristics flags value !");

		strcat_s( szTmp5, sizeof( szTmp5)-1, "\r\n\t\t}");
	}

	typedef PIMAGE_NT_HEADERS (__stdcall *fpCheckSumMappedFile)( PVOID, DWORD, PDWORD, PDWORD);
	fpCheckSumMappedFile	fpCSMF;
	HMODULE					hMod = LoadLibraryA("imagehlp.dll");
	DWORD					dwComputedCheckSum = 0, 
							dwOriginalCheckSum = 0;
	if( hMod)
	{
		fpCSMF = (fpCheckSumMappedFile)GetProcAddress( hMod, "CheckSumMappedFile");
		if( fpCSMF != NULL)
		{
			dwOriginalCheckSum = dwComputedCheckSum = 0;
			fpCSMF( g_lpFileMappedOffset, (dwSizeLow+dwSizeHigh-1), &dwOriginalCheckSum, &dwComputedCheckSum );
		}
		FreeLibrary( hMod);
	}


	/* Preparing first skeleton of a log */
	sprintf_s( g_szDumpedPE,	g_dwDumpedPESize-1, 
							"\r\nPEInfo v0.6 by MGeeky, File research, dumped semi-raw PE Headers\r\n"
							"Current time/date stamp:\t( %s )\r\n"
							"----------------------------------------------------------------------------\r\n"
							"\r\nFile:\t\"%s\"\r\nFile size:\t%lu bytes\r\n"
							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x00 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"DOS Header (IMAGE_DOS_HEADER) (sizeof: %dd)\r\n{\r\n\te_magic:\t\t%X;\t(%c%c)\t// Signature\r\n\t"
							"e_cblp:\t\t%X;\t\t// Bytes last page of file\r\n\te_cp:\t\t%X;\t\t// pages in file\r\n\t"
							"e_crlc:\t\t%X;\t\t// Relocations\r\n\te_cparhdr:\t%X;\t\t// Size of header in paragraphs\r\n\t"
							"e_minalloc:\t%X;\t\t// Min. extra paragraphs\r\n\te_maxalloc:\t%X;\t\t// Max. extra paragraphs\r\n\t"
							"e_ss:\t\t%X;\t\t// Initial SS\r\n\te_sp:\t\t%X;\t\t// Initial SP\r\n\te_"
							"csum:\t\t%X;\t(valid: %X)\t// Checksum\r\n\te_ip:\t\t%X;\t\t// Initial IP\r\n\t"
							"e_cs:\t\t%X;\t\t// Initial CS\r\n\te_lfarlc:\t\t%X;\t\t// offset to Relocation Table\r\n\t"
							"e_ovno:\t\t%X;\t\t// Overlay number\r\n\te_res:\t\t%X;\t\t// Reserved."
							"\r\n\te_oemid:\t\t%X;\t\t// OEM Identifier\r\n\te_oeminfo:\t%X;\t\t// OEM Information"
							"\r\n\te_res2:\t\t%X;\t\t// Reserved.\r\n\te_lfanew:\t%X;\t\t// Offset to PE header\r\n};\r\n"

							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x01 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"DOS STUB - Dumped %d bytes\r\n{\r\n%s\r\n}\r\n"

							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x02 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"NT Headers (IMAGE_NT_HEADERS32) (sizeof: %dd)"
							"\r\n{\r\n\tSignature:\t\t\t\t%X;\t(PE)\r\n"
							"\r\n\tFileHeader (IMAGE_FILE_HEADER) (sizeof: %dd)\r\n\t{\r\n"
							"\t\tMachine:\t\t\t\t%X;\r\n\t\t\t\t%s\r\n\t\tNumberOfSections:\t\t\t%X;\r\n\t\tTimeDateStamp:\t\t\t%X;"
							"\t\t\t\t\t(%s);\r\n\t\tPointerToSymbolTable:\t\t%X;\r\n\t\tNumberOfSymbols:\t\t\t%X;\r\n\t\t"
							"SizeOfOptionalHeader:\t\t%X;\r\n\t\tCharacteristics:\t\t\t%X;\r\n\t\t{%s\r\n\t\t}\r\n\t};\r\n"
							"\r\n\tOptionalHeader (IMAGE_OPTIONAL_HEADER32) (sizeof: %dd)\r\n\t{\r\n"
							"\t\tMagic:\t\t\t\t%X;\r\n\t\tMajorLinkerVersion:\t\t\t%X;\r\n\t\tMinorLinkerVersion:"
							"\t\t\t%X;\r\n\t\tSizeOfCode:\t\t\t%X;\r\n\t\tSizeOfInitializedData:\t\t%X;\r\n\t\tSizeOfUninitializedData"
							":\t\t%X;\r\n\t\tAddressOfEntryPoint:\t\t%X;\r\n\t\tBaseOfCode:\t\t\t%X;\r\n\t\tBaseOfData"
							":\t\t\t%X;\r\n\t\tImageBase:\t\t\t%X;\r\n\t\tSectionAlignment:\t\t\t%X;\r\n\t\tFileAlignment"
							":\t\t\t%X;\r\n\t\tMajorOperatingSystemVersion:\t%X;\r\n\t\tMinorOperatingSystemVersion"
							":\t%X;\r\n\t\tMajorImageVersion:\t\t%X;\r\n\t\tMinorImageVersion:\t\t\t%X;\r\n\t\tMajorSubsystemVersion"
							":\t\t%X;\r\n\t\tMinorSubsystemVersion:\t\t%X;\r\n\t\tWin32VersionValue:\t\t\t%X;\r\n\t\tSizeOfImage"
							":\t\t\t%X;\r\n\t\tSizeOfHeaders:\t\t\t%X;\r\n\t\tCheckSum:\t\t\t%X;\t(valid: %X)\r\n\t\tSubsystem:\t\t\t%X;%s"//\r\n\t\t
							"\r\n\t\tDllCharacteristics:\t\t\t%X;%s\r\n\t\tSizeOfStackReserve:\t\t%X;\r\n\t\tSizeOfStackCommit"
							":\t\t%X;\r\n\t\tSizeOfHeapReserve:\t\t%X;\r\n\t\tSizeOfHeapCommit:\t\t\t%X;\r\n\t\tLoaderFlags"
							":\t\t\t%X;\r\n\t\tNumberOfRvaAndSizes:\t\t%X;\r\n\t}; // OptionalHeader\r\n\r\n}; // NT Headers",

							ctime( &tNowTDS ), g_szFilePath, (dwSizeLow+dwSizeHigh), sizeof(IMAGE_DOS_HEADER), 
							g_image_dos_header.e_magic, HexChar( (char)g_image_dos_header.e_magic), 
							HexChar( *((char*)(DWORD(&g_image_dos_header)+1)) ),
							g_image_dos_header.e_cblp, g_image_dos_header.e_cp, g_image_dos_header.e_crlc,  
							g_image_dos_header.e_cparhdr, g_image_dos_header.e_minalloc, g_image_dos_header.e_maxalloc, 
							g_image_dos_header.e_ss, g_image_dos_header.e_sp, g_image_dos_header.e_csum, (!(dwSizeLow+dwSizeHigh)),
							g_image_dos_header.e_ip, g_image_dos_header.e_cs, g_image_dos_header.e_lfarlc, 
							g_image_dos_header.e_ovno, g_image_dos_header.e_res, g_image_dos_header.e_oemid, 
							g_image_dos_header.e_oeminfo, g_image_dos_header.e_res2, g_image_dos_header.e_lfanew,
							g_dwDOS_STUB_Length+1, szStub, sizeof(IMAGE_NT_HEADERS32), IMAGE_NT_SIGNATURE, 
							sizeof(IMAGE_FILE_HEADER), g_image_file_header.Machine, szTmp3, g_image_file_header.NumberOfSections,
							g_image_file_header.TimeDateStamp, ctime(&tTimeDateStamp), 
							g_image_file_header.PointerToSymbolTable,
							g_image_file_header.NumberOfSymbols, g_image_file_header.SizeOfOptionalHeader,
							g_image_file_header.Characteristics, szTmp2, sizeof(IMAGE_OPTIONAL_HEADER32), 
							g_image_optional_header.Magic, g_image_optional_header.MajorLinkerVersion,
							g_image_optional_header.MinorLinkerVersion, g_image_optional_header.SizeOfCode,
							g_image_optional_header.SizeOfInitializedData, 
							g_image_optional_header.SizeOfUninitializedData, g_image_optional_header.AddressOfEntryPoint,
							g_image_optional_header.BaseOfCode, g_image_optional_header.BaseOfData, 
							g_image_optional_header.ImageBase, g_image_optional_header.SectionAlignment, 
							g_image_optional_header.FileAlignment, g_image_optional_header.MajorOperatingSystemVersion,
							g_image_optional_header.MinorOperatingSystemVersion, g_image_optional_header.MajorImageVersion, 
							g_image_optional_header.MinorImageVersion, g_image_optional_header.MajorSubsystemVersion, 
							g_image_optional_header.MinorSubsystemVersion, g_image_optional_header.Win32VersionValue,
							g_image_optional_header.SizeOfImage, g_image_optional_header.SizeOfHeaders, 
							g_image_optional_header.CheckSum, dwComputedCheckSum, g_image_optional_header.Subsystem, szTmp4,
							g_image_optional_header.DllCharacteristics, szTmp5, g_image_optional_header.SizeOfStackReserve,
							g_image_optional_header.SizeOfStackCommit, g_image_optional_header.SizeOfHeapReserve, 
							g_image_optional_header.SizeOfHeapCommit, g_image_optional_header.LoaderFlags, 
							g_image_optional_header.NumberOfRvaAndSizes
	);

	/* Addinational info for sections loop */
	ZeroMemory(szTmp2, dwTmpSize);
	sprintf_s(szTmp, sizeof(szTmp)-1, "\t#\tSize\tVA\r\n");

	free( (void*)szStub);
	szStub = NULL;

	/* A tables to pointers of chars. 
	 * This names is next names of DataDirectory indexes 
	 */
	char *szOptionalHeadersNames[ ] = 
	{
		"Export Symbols", "Import Symbols", "Resources", "Exception Table", 
		"Certificate Table (security)", "Base Relocation", "Debug", "Architecture (reserved)", "GlobalPtr",
		"Thread Local Storage [TLS]", "Load Configuration", "Bound Import",
		"Import Address Table", "Delay-Load Import Descriptor", "CLR Runtime Descriptor / COM", "Reserved"
	};

	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, "\r\n\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-"
						" [ 0x03 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
						"IMAGE_OPTIONAL_HEADER32->DataDirectory dump:\r\n{\r\n");
	
	/* A sections information loop.
	 * This loop prepares infos about sections from 
	 * IMAGE_DATA_DIRECTORY structure values.
	 */
	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, 
			"\t#\tVA\tSize\r\n\t--------------------------------------\r\n");

	for(unsigned i = 0; i < 16; i++)
	{
		sprintf_s(szTmp, "\t%d.)\t%X\t%X\t\t// %s\r\n", i,
				g_image_optional_header.DataDirectory[i].VirtualAddress,
				g_image_optional_header.DataDirectory[i].Size, 
				szOptionalHeadersNames[i]);
		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, szTmp);
	}

	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, "\r\n}; // DataDirectory\r\n");
	
	ZeroMemory(szTmp, dwTmpSize);

	char szName[9] = "";
	
	/* Appending extra, cosmetical chars */
	sprintf_s(szTmp, sizeof(szTmp)-1, "%dd)\r\n{\r\n\t", sizeof(IMAGE_SECTION_HEADER) );
	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1,	"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x04 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
						"All Sections Info (gathered from IMAGE_SECTION_HEADERs ) (sizeof: ");
	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, szTmp);

	for(int i = 0; i < g_image_file_header.NumberOfSections; i++)
	{
		pImage_section_header = &g_image_section_header[i];

		strncpy_s(szName, sizeof(szName)-1, (const char*)pImage_section_header->Name, 7);
		szName[strlen(szName)+1] = '\0';

		sprintf_s( szTmp, sizeof szTmp, "%s\t", szName);
		if( i % 8 == 0)strcat( szTmp, "\n");

		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, szTmp);
	}

	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, "\r\n\r\n");

	/* Important loop.
	 * In this loop we will describe every section,
	 * by using informations saved in each IMAGE_SECTION_HEADER
	 * structure. 
	 */

	for(int i = 0; i < g_image_file_header.NumberOfSections; i++)
	{
		pImage_section_header = &g_image_section_header[i];

		strncpy_s(szName, sizeof(szName)-1, (const char*)pImage_section_header->Name, 7);
		szName[strlen(szName)+1] = '\0';

		ZeroMemory(szTmp, dwTmpSize);
		sprintf_s(szTmp, sizeof(szTmp)-1, "\t// ::::::::::::::::::\r\n\tIMAGE_SECTION_HEADER[ %d ]\r\n\t{"
					"\r\n\t\tName:\t\t\t\"%s\";\r\n\t\tVirtualSize:\t\t%X;\r\n\t\tVirtualAddress:\t\t%X;\r\n\t\t"
					"SizeOfRawData:\t\t%X;\r\n\t\tPointerToRawData:\t\t%X;\r\n\t\tPointerToRelocations:\t%X;\r\n\t"
					"\tPointerToLinenumbers:\t%X;\r\n\t\tNumberOfRelocations:\t%X;\r\n\t"
					"\tNumberOfLinenumbers:\t%X;\r\n\t\tCharacteristics:\t\t%X;\r\n\t\t{\r\n",
					
					i, szName, pImage_section_header->Misc.VirtualSize,
					pImage_section_header->VirtualAddress, pImage_section_header->SizeOfRawData,
					pImage_section_header->PointerToRawData, pImage_section_header->PointerToRelocations,
					pImage_section_header->PointerToLinenumbers, pImage_section_header->NumberOfRelocations,
					pImage_section_header->NumberOfLinenumbers, pImage_section_header->Characteristics
		);


		/* 
		* Here we will iterate every section, and prepare full information
		* block about it. 
		*/

		if( pImage_section_header->Characteristics & IMAGE_SCN_CNT_CODE )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Section contains executable code;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Section contains initialized data;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Section contatins uninitialized data;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_LNK_INFO )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Section contains informations for use by the Linker;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_LNK_REMOVE )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Compilator gives informations to linker;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_LNK_COMDAT )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Contains Common Block Data (CBD);\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Containts extended relocations;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_DISCARDABLE )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Can be removed from memory;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Section is not cached;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_NOT_PAGED )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Section cannot be paged;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_SHARED )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Shared section;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Executing code allowed;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_READ )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Read from the section is allowed;\r\n");
		if( pImage_section_header->Characteristics & IMAGE_SCN_MEM_WRITE )
			strcat_s(szTmp, sizeof(szTmp)-1, "\t\t\t- Write to the section is allowed;\r\n");

		// appending to main string variable
		strcat_s(szTmp, sizeof(szTmp)-1, "\t\t};\r\n\t};\r\n\r\n");
		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, szTmp);
	}


	/* Here we appending some chars */
	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, "\r\n}; // Sections Info\r\n\r\n" );


	/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */

	
	// Reading Import Table if available.
	if( g_image_optional_header.DataDirectory[1].Size > 0 )
	{
		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, 
							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-"
							" [ 0x05 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"PE Import data view (IAT + IMAGE_IMPORT_DESCRIPTORs)\r\n{\r\n");

		List_IAT(g_szDumpedPE, g_dwDumpedPESize - 1);

		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, "\r\n\r\n}; // PE Import Table\r\n\r\n");
	}else
	{
		if( g_image_optional_header.Subsystem != IMAGE_SUBSYSTEM_NATIVE )
		{
			/*MessageBoxA(NULL,	"WARNING !\r\nThere is no valid Import Table available in file !"
								"\r\nIt may be meaning that the file is native/broken/encrypted/ or "
								"this PE file just have no Import Table.", 
								"Warning!", MB_ICONWARNING|MB_APPLMODAL);
			*/
		}
	}

	// Reading Export Table if available.
	if( g_image_optional_header.DataDirectory[0].Size > 0x10 )
	{
		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, 
							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x06 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"PE Export data view (EAT + IMAGE_EXPORT_DIRECTORY)\r\n{\r\n");

		List_EAT(g_szDumpedPE, g_dwDumpedPESize - 1);

		strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, "}; // PE Export Table\r\n\r\n");
	}

	bool bIsExportAvailable = (g_image_optional_header.DataDirectory[0].Size > 0x10);

	// Debug
	memset( szTmp, 0, sizeof szTmp);
	DumpDEBUGInfo( szTmp);
	if( strlen( szTmp) > 0) strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, szTmp);

	// Delay-Load Import Tables
	DumpDelayLoadIAT ( g_szDumpedPE );

	/* Adding some extra chars (for cosmetical purposes ) */

	ZeroMemory(szTmp, dwTmpSize );
	g_dwPreparingLogTime = ( GetTickCount() - g_dwPreparingLogTime + 100) / 10;

	strcat_s(g_szDumpedPE,	g_dwDumpedPESize-1, "\r\n\r\n\r\n------------------------------------"
												"----------------------------------------\r\n");
	sprintf_s(szTmp, dwTmpSize - 1, "\r\n[?] Log prepared in\t\t\t\t%dms;"
				"\r\n[?] Log length:\t\t\t\t%lu bytes;", g_dwPreparingLogTime, strlen(g_szDumpedPE));	

	strcat_s(g_szDumpedPE, g_dwDumpedPESize-1, szTmp);


	// Setting prepared log to the read-only editbox window. 

	SendDlgItemMessageA( g_hMain, IDC_EDIT1, EM_LIMITTEXT, (WPARAM)strlen(g_szDumpedPE) + 3, 0);
	if(GetLastError()) Error( "SendDlgItemMessageA has failed !");
	
	SetWindowTextA( GetDlgItem(g_hMain, IDC_EDIT1), g_szDumpedPE);
	if(GetLastError()) Error( "SetWindowTextA has failed !");



	if( !(g_image_file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
		(strstr( g_szFilePath, ".exe") != NULL || strstr( g_szFilePath, ".EXE") != NULL ) )
		MessageBoxA(NULL, "WARNING! This PE .EXE file has not setted IMAGE_FILE_EXECUTABLE_IMAGE"
						" flag in PE->FileHeader.Characteristics! This application would not be"
						" loaded by OS Loader. Please fix it by EditHeaders function.",
						"Critical warning", MB_ICONWARNING|MB_APPLMODAL );
	
	/* Ending thread */

	EnableWindow( GetDlgItem( g_hMain, IDC_BUTTON9), TRUE);


	_endthreadex(0);
	return 0;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */

VOID FillSecondCombo(DWORD dwSelected)
{

	SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_RESETCONTENT, 0, 0);

	if(dwSelected == 0)
	{
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_magic" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_cblp" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_cp" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_crlc" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_cparhdr" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_minalloc" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_maxalloc" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_ss" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_sp" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_csum" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_ip" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_cs" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_lfarlc" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_ovno" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_oemid" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_oeminfo" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"e_lfanew" );	

		if(GetLastError() )
			Error( "Error while adding strings to second combobox");

	}else if( dwSelected == 1)
	{
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"Machine" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"NumberOfSections" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"TimeDateStamp" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"PointerToSymbolTable" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"NumberOfSymbols" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfOptionalHeader" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"Characteristics" );

		if(GetLastError() )
			Error( "Error while adding strings to second combobox");
		
	}else if( dwSelected == 2)
	{
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"Magic" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MajorLinkerVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MinorLinkerVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfCode" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfInitializedData" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfUnInitializedData" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"AddressOfEntryPoint" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"BaseOfCode" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"BaseOfData" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"ImageBase" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SectionAlignment" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"FileAlignment" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MajorOperatingSystemVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MinorOperatingSystemVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MajorImageVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MinorImageVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MajorSubsystemVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"MinorSubsystemVersion" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"Win32VersionValue" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfImage" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfHeaders" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"CheckSum" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"Subsystem" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"DllCharacteristcis" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfStackReserve" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfStackCommit" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfHeapReserver" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"SizeOfHeapCommit" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"LoaderFlags" );
		SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_ADDSTRING, 0, (LPARAM)"NumberOfRvaAndSizes" );

		if(GetLastError() )
			Error( "Error while adding strings to second combobox");
		
	}
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This is function for WM_COMMAND message in EditValueDialogProcedure.

VOID OnCommand_EditValueDialog(WPARAM wParam, LPARAM lParam)
{
	/* -------------------------- Variables ------ */
	DWORD dwCtrlID = LOWORD(wParam);
	char szTmp[32] = "";

	DWORD dwIndex1;
	/* -------------------------- Variables ------ */

	if(IsDlgButtonChecked(g_hEditValueDialog, IDC_RADIO1) )		dwIndex1 = 0;
	else if(IsDlgButtonChecked(g_hEditValueDialog, IDC_RADIO2) )	dwIndex1 = 1;
	else if(IsDlgButtonChecked(g_hEditValueDialog, IDC_RADIO3) )	dwIndex1 = 2;

	if( dwCtrlID == IDCANCEL) SendMessageA(g_hEditValueDialog, WM_CLOSE, 0, 0);
	else if( dwCtrlID == IDC_VALUE )
	{
		/* -------------------------- Variables ------ */
		DWORD dwIndex2 = SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_GETCURSEL, 0, 0);

		/* -------------------------- Variables ------ */
	
		if( dwIndex1 == 0)
		{
			switch( dwIndex2 )
			{
			case 0: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_magic); break;
			case 1: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_cblp); break;
			case 2: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_cp); break;
			case 3: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_crlc); break;
			case 4: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_cparhdr); break;
			case 5: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_minalloc); break;
			case 6: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_maxalloc); break;
			case 7: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_ss); break;
			case 8: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_sp); break;
			case 9: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_csum); break;
			case 10: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_ip); break;
			case 11: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_cs); break;
			case 12: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_lfarlc); break;
			case 13: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_ovno); break;
			case 14: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_oemid); break;
			case 15: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_oeminfo); break;
			case 16: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_dos_header.e_lfanew); break;
			}

		}
		else if( dwIndex1 == 1)
		{
			switch( dwIndex2 )
			{
			case 0: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.Machine); break;
			case 1: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.NumberOfSections); break;
			case 2: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.TimeDateStamp); break;
			case 3: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.PointerToSymbolTable); break;
			case 4: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.NumberOfSymbols); break;
			case 5: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.SizeOfOptionalHeader); break;
			case 6: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_file_header.Characteristics); break;
			}
		}
		else  if( dwIndex1 == 2)
		{
			switch( dwIndex2 )
			{
			case 0: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.Magic); break;
			case 1: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MajorLinkerVersion); break;
			case 2: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MinorLinkerVersion); break;
			case 3: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfCode); break;
			case 4: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfInitializedData); break;
			case 5: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfUninitializedData); break;
			case 6: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.AddressOfEntryPoint); break;
			case 7: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.BaseOfCode); break;
			case 8: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.BaseOfData); break;
			case 9: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.ImageBase); break;
			case 10: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SectionAlignment); break;
			case 11: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.FileAlignment); break;
			case 12: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MajorOperatingSystemVersion); break;
			case 13: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MinorOperatingSystemVersion); break;
			case 14: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MajorImageVersion); break;
			case 15: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MinorImageVersion); break;
			case 16: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MajorSubsystemVersion); break;
			case 17: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.MinorSubsystemVersion); break;
			case 18: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.Win32VersionValue); break;
			case 19: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfImage); break;
			case 20: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfHeaders); break;
			case 21: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.CheckSum); break;
			case 22: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.Subsystem); break;
			case 23: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.DllCharacteristics); break;
			case 24: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfStackReserve); break;
			case 25: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfStackCommit); break;
			case 26: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfHeapReserve); break;
			case 27: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.SizeOfHeapCommit); break;
			case 28: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.LoaderFlags); break;
			case 29: sprintf_s(szTmp, sizeof(szTmp)-1, "%X", g_image_optional_header.NumberOfRvaAndSizes); break;
			}
		}
		
		SetWindowTextA(GetDlgItem(g_hEditValueDialog, IDC_OLD_VALUE), szTmp);
	}
	else if( dwCtrlID == IDC_SET_VALUE)
	{
		/* -------------------------- Variables ------ */
		char szNewValue[16] = "";
		GetDlgItemTextA(g_hEditValueDialog, IDC_NEW_VALUE, szNewValue, 15);
		int nValue = strtol(szNewValue, NULL, 16);

		DWORD dwIndex2 = SendMessageA(GetDlgItem(g_hEditValueDialog, IDC_VALUE), CB_GETCURSEL, 0, 0);

		/* -------------------------- Variables ------ */


		if ( dwIndex1 == 0)
		{
			switch( dwIndex2)
			{
			case 0: g_image_dos_header.e_magic = nValue; break;
			case 1: g_image_dos_header.e_cblp = nValue; break;
			case 2: g_image_dos_header.e_cp = nValue; break;
			case 3: g_image_dos_header.e_crlc = nValue; break;
			case 4: g_image_dos_header.e_cparhdr = nValue; break;
			case 5: g_image_dos_header.e_minalloc = nValue; break;
			case 6: g_image_dos_header.e_maxalloc = nValue; break;
			case 7: g_image_dos_header.e_ss = nValue; break;
			case 8: g_image_dos_header.e_sp = nValue; break;
			case 9: g_image_dos_header.e_csum = nValue; break;
			case 10: g_image_dos_header.e_ip = nValue; break;
			case 11: g_image_dos_header.e_cs = nValue; break;
			case 12: g_image_dos_header.e_lfarlc = nValue; break;
			case 13: g_image_dos_header.e_ovno = nValue; break;
			case 14: g_image_dos_header.e_oemid = nValue; break;
			case 15: g_image_dos_header.e_oeminfo = nValue; break;
			case 16: g_image_dos_header.e_lfanew = nValue; break;
			}

		}else if ( dwIndex1 == 1)
		{
			switch( dwIndex2)
			{
			case 0: g_image_file_header.Machine = nValue; break;
			case 1: g_image_file_header.NumberOfSections = nValue; break;
			case 2: g_image_file_header.TimeDateStamp = nValue; break;
			case 3: g_image_file_header.PointerToSymbolTable = nValue; break;
			case 4: g_image_file_header.NumberOfSymbols = nValue; break;
			case 5: g_image_file_header.SizeOfOptionalHeader = nValue; break;
			case 6: g_image_file_header.Characteristics = nValue; break;
			}

		}else if( dwIndex1 == 2)
		{
			switch( dwIndex2)
			{
			case 0: g_image_optional_header.Magic = nValue; break;
			case 1: g_image_optional_header.MajorLinkerVersion = nValue; break;
			case 2: g_image_optional_header.MinorLinkerVersion = nValue; break;
			case 3: g_image_optional_header.SizeOfCode = nValue; break;
			case 4: g_image_optional_header.SizeOfInitializedData = nValue; break;
			case 5: g_image_optional_header.SizeOfUninitializedData = nValue; break;
			case 6: g_image_optional_header.AddressOfEntryPoint = nValue; break;
			case 7: g_image_optional_header.BaseOfCode = nValue; break;
			case 8: g_image_optional_header.BaseOfData = nValue; break;
			case 9: g_image_optional_header.ImageBase = nValue; break;
			case 10: g_image_optional_header.SectionAlignment = nValue; break;
			case 11: g_image_optional_header.FileAlignment = nValue; break;
			case 12: g_image_optional_header.MajorOperatingSystemVersion = nValue; break;
			case 13: g_image_optional_header.MinorOperatingSystemVersion = nValue; break;
			case 14: g_image_optional_header.MajorImageVersion = nValue; break;
			case 15: g_image_optional_header.MinorImageVersion = nValue; break;
			case 16: g_image_optional_header.MajorSubsystemVersion = nValue; break;
			case 17: g_image_optional_header.MinorSubsystemVersion = nValue; break;
			case 18: g_image_optional_header.Win32VersionValue = nValue; break;
			case 19: g_image_optional_header.SizeOfImage = nValue; break;
			case 20: g_image_optional_header.SizeOfHeaders = nValue; break;
			case 21: g_image_optional_header.CheckSum = nValue; break;
			case 22: g_image_optional_header.Subsystem = nValue; break;
			case 23: g_image_optional_header.DllCharacteristics = nValue; break;
			case 24: g_image_optional_header.SizeOfStackReserve = nValue; break;
			case 25: g_image_optional_header.SizeOfStackCommit = nValue; break;
			case 26: g_image_optional_header.SizeOfHeapReserve = nValue; break;
			case 27: g_image_optional_header.SizeOfHeapCommit = nValue; break;
			case 28: g_image_optional_header.LoaderFlags = nValue; break;
			case 29: g_image_optional_header.NumberOfRvaAndSizes = nValue; break;
			}

		}

	}else if( dwCtrlID == IDOK)
	{
		DWORD dwRes = MessageBoxA(NULL,	"Do you really want to save all headers to file?"
							"This operation may damage the file, so it could lead to that, "
							"that this program will not start."
							"\r\n\r\nDo you really sure of that what you do?",
							"WARNING !", MB_ICONWARNING|MB_YESNO|MB_APPLMODAL|MB_DEFBUTTON2);
		if( dwRes == IDYES)
		{
			dwRes = 0;
			dwRes = MessageBoxA(NULL, "Do you want to make backup of this file?", 
								"Question", MB_ICONQUESTION|MB_YESNO|MB_APPLMODAL|MB_DEFBUTTON1);

			if(dwRes == IDYES)
			{
				char szNewFileName[MAX_PATH+1] = "";
				strcpy_s(szNewFileName, sizeof(szNewFileName)-1, g_szFilePath);
				strcat_s(szNewFileName, sizeof(szNewFileName)-1, ".bak");

				if(! CopyFileA(g_szFilePath, szNewFileName, FALSE))
				{
					dwRes = MessageBoxA( NULL, "Error while creating backup of PE file.\r\n"
							"Saving headers to the file should be terminated, if you"
							" do not want to modify original file.\r\n"
							"Do you want to continue and write headers to original file?\r\nWITHOUT BACKUP?",
							"Error while creating BACKUP file", MB_ICONQUESTION|MB_YESNO|MB_APPLMODAL|MB_DEFBUTTON2);
					if(dwRes == IDNO) return;
				}
			}
			
			if(! SaveHeadersToFile())
			{
				Error( "There was an unrecognized error, while saving headers to the file!\r\n"
						"Operation terminated. Data not written to the file.");
			}
		} // if( dwRes == IDYES)
	} // else if( dwCtrlID == IDOK)


}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
//This function writes three headers to file.

BOOL SaveHeadersToFile()
{
	
	/* -------------------------- Variables ------ */
	DWORD dwBytes = 0;
	DWORD nOffset;

	HANDLE hFile;
	/* -------------------------- Variables ------ */

	/* Open the file */
	hFile = CreateFileA(g_szFilePath, GENERIC_WRITE, 
						FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if( hFile == INVALID_HANDLE_VALUE || GetLastError() )
	{
		char szTmp[60] = "";
		sprintf_s(szTmp, sizeof(szTmp)-1, "Cannot open file (\"%s\") !", g_szFilePath);
		Error( szTmp);
		return FALSE;
	}

	/* Write IMAGE_DOS_HEADER */
	WriteBytes(hFile, (LPCVOID)&g_image_dos_header, sizeof(g_image_dos_header) );

	/* Setting file pointer to IMAGE_NT_HEADERS offset in file */
    if ((nOffset = 
		SetFilePointer(hFile, g_image_dos_header.e_lfanew + sizeof(DWORD), NULL, FILE_BEGIN)
	) == 0xFFFFFFFF){
        Error( "SetFilePointer failed while write.");
        return FALSE;
	}

	/* Write IMAGE_FILE_HEADER */
	WriteBytes( hFile, (LPCVOID)&g_image_file_header, IMAGE_SIZEOF_FILE_HEADER );
	 
	/* Write IMAGE_OPTIONAL_HEADER32 */
	WriteBytes( hFile, (LPCVOID)&g_image_optional_header, sizeof(IMAGE_OPTIONAL_HEADER32) );

	/* Close the file */
	CloseHandle( hFile);

	return TRUE;
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
//This function writes log created by PEInfo to selected by user file.

BOOL SaveLogToFile()
{

// Set this macro to 1 if you want to use chars table string style
// (without allocating memory for buffer)
#define ALLOCATE_BUFFER	0

	/* -------------------------- Variables ------ */

	OPENFILENAMEA	ofn;
	const DWORD dwFileNameSize = MAX_PATH+1;

#if ALLOCATE_BUFFER == 1
	char			*szFileName;
#else
	char			szFileName[dwFileNameSize] = "";
#endif

	char			szTmp[128+1] = "";
	char			lpstrFilter[] = "simply text file (*.txt)\0*.txt\0"
									"log file (*.log)\0*.log\0All Files (*.*)\0*.*\0";
	HANDLE			hFile;

	/* -------------------------- Variables ------ */

#if ALLOCATE_BUFFER == 1
	szFileName = (char*)malloc(dwFileNameSize);
	if( !szFileName )
	{
		Error( "Cannot alloc memory for variable which must handle name of log file.");
		return FALSE;
	}
#endif

	ZeroMemory( szFileName, dwFileNameSize);
	ZeroMemory(&ofn, sizeof(ofn) );
	
	int iLen = int( ( g_szFilePath - (strrchr(g_szFilePath, '\\') + 1) )
					- ( g_szFilePath - (strrchr(g_szFilePath, '.')) ) );
	strncpy_s(szTmp, sizeof(szTmp)-1, (const char*)( strrchr(g_szFilePath, '\\') + 1 ), iLen);

	sprintf_s( szFileName, dwFileNameSize-1, "%s_PEhdrs.txt", szTmp );
	
	ofn.lStructSize		= sizeof( OPENFILENAMEA);
	ofn.Flags			= OFN_NONETWORKBUTTON | OFN_NOCHANGEDIR | OFN_OVERWRITEPROMPT;
	ofn.hInstance		= g_hInstance;
	ofn.hwndOwner		= g_hMain;
	ofn.lpstrFilter		= lpstrFilter;
	ofn.lpstrDefExt		= "txt";
	ofn.nMaxFile		= dwFileNameSize-1;
	ofn.lpstrFile		= szFileName;

	ZeroMemory( szTmp, sizeof(szTmp));
	sprintf_s(szTmp, sizeof(szTmp)-1, "[ %s ] Save, semi-raw PE dump, log to file. Log length: %d bytes.", 
			(strrchr(g_szFilePath, '\\') + 1), strlen(g_szDumpedPE)-1 );

	ofn.lpstrTitle		= szTmp;

	if(!GetSaveFileNameA(&ofn) || CommDlgExtendedError() || GetLastError() )
	{
		char szError[128] = "";
		sprintf_s(szError, sizeof(szError)-1, "Error while typing log file. GetSaveFileNameA failed. (%s() )",
												(GetLastError()? "GLE" : "CDEE"));
	#if ALLOCATE_BUFFER == 1
		free((void*)szFileName);
	#endif

		__Error(szError, ((CommDlgExtendedError() )? CommDlgExtendedError() : GetLastError() ), 
				__LINE__, __FUNCTION__);
		return FALSE;	
	}

	DeleteFileA( szFileName);
	SetLastError(0);

	hFile = CreateFileA( szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwErr = GetLastError();

#if ALLOCATE_BUFFER == 1
	free((void*)szFileName);
#endif

	if( hFile == INVALID_HANDLE_VALUE || dwErr )
	{
		char szError[65] = "";
		sprintf_s(szError, sizeof(szError)-1, "Cannot open file to save log. !");

	#if ALLOCATE_BUFFER == 1
		free((void*)szFileName);
	#endif
		__Error( szError, dwErr, __LINE__, __FUNCTION__);

		return FALSE;
	}

	WriteBytes( hFile, (LPCVOID)g_szDumpedPE, strlen( g_szDumpedPE) );

	CloseHandle( hFile);

	
	return TRUE;

}


/////////////////////////////////////////////////////////////////////
/////// Start analysing file

VOID AnalyseFile( LPSTR lpFileName)
{

	strcpy( g_szFilePath, lpFileName);	

	char szTmp[ 100] = "";
	ZeroMemory(szTmp, 100);
	if(strlen(g_szFilePath) < 80)
		sprintf_s(szTmp, sizeof(szTmp)-1, "PEInfo v0.6 - \"%s\"", g_szFilePath);
	else sprintf_s(szTmp, sizeof(szTmp)-1, "PEInfo v0.6 - \"%s\"", 
			(char*)strrchr((const char*)g_szFilePath, (int)'\\')+1);

	SetWindowTextA(g_hMain, szTmp);
	SetWindowTextA(GetDlgItem(g_hMain, IDC_FILEPATH), lpFileName);

	EnableWindow(GetDlgItem(g_hMain, IDC_BUTTON5), TRUE);
	EnableWindow(GetDlgItem(g_hMain, IDC_BUTTON6), TRUE);
	EnableWindow(GetDlgItem(g_hMain, IDC_BUTTON7), TRUE);


	// Mapping file to the memory
	{
		HANDLE hFile, hMap;
		DWORD dwSizeLow, dwSizeHigh;

		hFile = CreateFileA(lpFileName, GENERIC_READ, 
							FILE_SHARE_READ, NULL, 
							OPEN_EXISTING, 0, NULL );
		if( hFile == INVALID_HANDLE_VALUE || GetLastError() )
		{
			char szTmp2[56] = "";
			sprintf_s(szTmp2, sizeof(szTmp2)-1, "Cannot open selected file to map ! (file: \"%s\"",
						lpFileName);
			Error( szTmp2);
			return;
		}

		// Getting size of file to map into the memory
		dwSizeLow = GetFileSize(hFile, &dwSizeHigh);

		// Creating map file object.
		hMap = CreateFileMappingA (hFile, NULL, PAGE_READONLY, dwSizeHigh, dwSizeLow, NULL);
		if( !hMap || GetLastError() )
		{
			CloseHandle( hFile );

			char szTmp2[56] = "";
			sprintf_s(szTmp2, sizeof(szTmp2)-1, "Cannot map file in PEInfo memory!");
			Error( szTmp2);
			return;
		}

		if( g_lpFileMappedOffset != NULL) 
			UnmapViewOfFile( g_lpFileMappedOffset );


		// Mapping file in process (PEInfo.exe) memory.
		g_lpFileMappedOffset = MapViewOfFile (hMap, FILE_MAP_READ, 0, 0, 0);
		if( g_lpFileMappedOffset == NULL || GetLastError() )
		{
			CloseHandle( hMap );
			CloseHandle( hFile );

			char szTmp2[56] = "";
			sprintf_s(szTmp2, sizeof(szTmp2)-1, "Cannot map view of file !");
			Error( szTmp2);
			return;
		}

		CloseHandle(hFile );
		CloseHandle( hMap );

	}

	ZeroMemory( g_szDumpedPE, g_dwDumpedPESize);

	CollectInformations( lpFileName);
}


//////////////////////////////////////////////////////////////////////
// Function return TRUE if data contains a valid path, or FALSE if it does not.

BOOL DoesDataHavePath( LPSTR lpData)
{
	if( (strstr(lpData, "\\") != NULL 
		&& isalpha(lpData[0]) 
		&& strstr(lpData, ":\\") != NULL
		&& strlen( lpData) > 3) )
	{
		if( NULL != strstr( lpData, ".exe") || NULL != strstr( lpData, ".dll") )
			 return TRUE;
		else return FALSE;
	}else return FALSE;
}


///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

LONG __stdcall _UnhandledExceptionFilter( _EXCEPTION_POINTERS *pExceptionInfo )
{
	char	szError[ 2048] = "";
	char	szContext[ 512] = "";
	char	szExceptionDesc[ 512] = "";
	char	szTmp[ 18] = "";

	// Building log about retrieved CONTEXT
	sprintf_s( szContext, sizeof( szContext)-1, 
					"===========   Context Dump  ===========\n"
					"EAX:\t%.8X\t\tECX:\t%.8X\nEDX:\t%.8X\t\tEBX:\t%.8X\nESP:\t%.8X\t\tEBP:\t%.8X\n"
					"ESI:\t%.8X\t\tEDI:\t%.8X\nEIP\t\t%.8X\n\nCS:\t%X\tDS:\t%X\tSS:\t%X\nES:"
					"\t%X\tFS:\t%X\tGS:\t%X\n\nEFlags:\t%X  ( OF:%d, DF:%d, IF:"
					"%d, TF:%d, SF:%d, ZF:%d, AF:%d, PF:%d, CF:%d )\n\nContextFlags"
					":\t%X\nDr0:\t%X\tDr1:\t%X\tDr2:\t%X\nDr3:\t%X\tDr6:\t%X\tDr7:\t%X\n",
					
					pExceptionInfo->ContextRecord->Eax, pExceptionInfo->ContextRecord->Ecx, 
					pExceptionInfo->ContextRecord->Edx, pExceptionInfo->ContextRecord->Ebx, 
					pExceptionInfo->ContextRecord->Esp, pExceptionInfo->ContextRecord->Ebp, 
					pExceptionInfo->ContextRecord->Esi, pExceptionInfo->ContextRecord->Edi, 
					pExceptionInfo->ContextRecord->Eip,

					pExceptionInfo->ContextRecord->SegCs, pExceptionInfo->ContextRecord->SegDs, 
					pExceptionInfo->ContextRecord->SegSs, pExceptionInfo->ContextRecord->SegEs, 
					pExceptionInfo->ContextRecord->SegFs, pExceptionInfo->ContextRecord->SegGs, 

					pExceptionInfo->ContextRecord->EFlags, 
					bool(pExceptionInfo->ContextRecord->EFlags & 2048 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 1024 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 512 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 256 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 128 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 64 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 32 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 16 ),
					bool(pExceptionInfo->ContextRecord->EFlags & 1 ),
					pExceptionInfo->ContextRecord->ContextFlags,
					pExceptionInfo->ContextRecord->Dr0, pExceptionInfo->ContextRecord->Dr1,
					pExceptionInfo->ContextRecord->Dr2, pExceptionInfo->ContextRecord->Dr3,
					pExceptionInfo->ContextRecord->Dr6, pExceptionInfo->ContextRecord->Dr7
		);

	// Is exception continuable?
	if( pExceptionInfo->ExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE)
		strcpy( szTmp, "Non-continuable");
	else strcpy( szTmp, "Continuable" );

	// Reading exception information about Access Violation
	char szTmp2[ 256] = "";
	if(pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION )
	{
		sprintf_s( szTmp2, sizeof( szTmp2)-1, "\nR/W:\t%s\nVA of inacessible data:\t%X\n" ,
					((bool(*((BYTE*)(pExceptionInfo->ExceptionRecord->ExceptionInformation))) )
						? "Attempted to write to an inaccessible address" :
						"Attempted to read the inaccessible data" ),
					DWORD((LPVOID)(DWORD(pExceptionInfo->ExceptionRecord->ExceptionInformation)+4) )
		);
	}

	// Building primary Exception log
	sprintf_s( szExceptionDesc, sizeof( szExceptionDesc)-1, 
										"Exception Code:\t%X  ( %d. ) -> %s\n"
										"Exception Address:\t\t%X\nNumber of parameters:\t%d\n%s\n",
										pExceptionInfo->ExceptionRecord->ExceptionCode,
										pExceptionInfo->ExceptionRecord->ExceptionCode,
										szTmp, pExceptionInfo->ExceptionRecord->ExceptionAddress, 
										pExceptionInfo->ExceptionRecord->NumberParameters, 
										szTmp2
	);

	// Copying to main error description buffer
	sprintf(	szError, "Handler has caught an unhandled EXCEPTION. Exception info:\n\n%s\n%s\n\n",
				szExceptionDesc, szContext );

	// Preparing message box
	UINT uMode = MB_ICONERROR|MB_APPLMODAL|MB_TASKMODAL;
	if( pExceptionInfo->ExceptionRecord->ExceptionFlags != EXCEPTION_NONCONTINUABLE){
		uMode |= MB_YESNO|MB_DEFBUTTON1;
		strcat( szError, "Do you want to Terminate this application ?");
	}
	else{
		uMode |= MB_OK;
		strcat( szError, "This application will be now TERMINATED. ");
	}

	UINT uID = MessageBoxA( NULL, szError, "Unhandled exception filter", uMode);

	// Perform action
	if( pExceptionInfo->ExceptionRecord->ExceptionFlags != EXCEPTION_NONCONTINUABLE)
	{
		if( uID == IDNO )	return EXCEPTION_CONTINUE_EXECUTION;
		else				goto TERMINATE;			
	}				

TERMINATE:
	ShowWindow( g_hMain, SW_HIDE);

	if( g_hDumpPEThread != INVALID_HANDLE_VALUE)
	{
		TerminateThread(g_hDumpPEThread, 0);
		CloseHandle(g_hDumpPEThread);
		g_hDumpPEThread = INVALID_HANDLE_VALUE;
	}

	ZeroMemory(g_szDumpedPE, g_dwDumpedPESize);

	/* Freeing resources */
	if(g_szDumpedPE != NULL) free((void*)g_szDumpedPE);
	g_szDumpedPE = NULL;

	if( g_lpFileMappedOffset != 0 ) UnmapViewOfFile( g_lpFileMappedOffset);
	g_lpFileMappedOffset = 0;

	TerminateProcess( GetCurrentProcess(), pExceptionInfo->ExceptionRecord->ExceptionCode );
	return pExceptionInfo->ExceptionRecord->ExceptionCode;
}



///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

DWORD DumpDEBUGInfo( LPSTR lpData)
{
	if( g_image_optional_header.DataDirectory[6].VirtualAddress == 0
		|| g_image_optional_header.DataDirectory[6].Size == 0 )   return 0;


	// Debug directory entry strcture, containing informations useful for debuggers 
	// (can be located at NT_HEADERS->OptionalHeader->DataDirectory[6].VirtualAddress)
	typedef struct _DEBUG_DIRECTORY_ENTRY 
	{
		DWORD	Characteristics;
		DWORD	TimeDateStamp;
		WORD	MajorVersion;
		WORD	MinorVersion;
		DWORD	Type;
		DWORD	SizeOfData;
		DWORD	AddressOfRawData;
		DWORD	PointerToRawData;
	} DEBUG_DIRECTORY_ENTRY, *PDEBUG_DIRECTORY_ENTRY;

	PDEBUG_DIRECTORY_ENTRY	pddeEntry = (PDEBUG_DIRECTORY_ENTRY)(DWORD(g_lpFileMappedOffset) 
			+ RVAToOffset(g_lpFileMappedOffset, g_image_optional_header.DataDirectory[6].VirtualAddress));

#ifndef _DBG_DEFINES__PEINFO
	#define _DBG_DEFINES__PEINFO

	#define	IMAGE_DEBUG_TYPE_UNKNOWN		0
	#define	IMAGE_DEBUG_TYPE_COFF			1
	#define	IMAGE_DEBUG_TYPE_CODEVIEW		2
	#define	IMAGE_DEBUG_TYPE_FPO			3
	#define	IMAGE_DEBUG_TYPE_MISC 			4
	#define	IMAGE_DEBUG_TYPE_EXCEPTION		5
	#define	IMAGE_DEBUG_TYPE_FIXUP			6
	#define	IMAGE_DEBUG_TYPE_OMAP_TO_SRC 	7
	#define	IMAGE_DEBUG_TYPE_OMAP_FROM_SRC 	8
	#define	IMAGE_DEBUG_TYPE_BORLAND		9
	#define	IMAGE_DEBUG_TYPE_RESERVED10		10
	#define	IMAGE_DEBUG_TYPE_CLSID			11
#endif
	
	char	szDebugEntryType[ 64] = "";

	if( pddeEntry->Type & IMAGE_DEBUG_TYPE_UNKNOWN)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "Unknown value (ignored)");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_COFF)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "COFF Debug informations");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_CODEVIEW)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "MS Visual C++ Debug Informations");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_FPO)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "FPO (Frame Pointer Omission) informations");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_MISC)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "Location of DBG file");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_EXCEPTION)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "A copy of .pdata section");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_FIXUP
			|| pddeEntry->Type & IMAGE_DEBUG_TYPE_RESERVED10
			|| pddeEntry->Type & IMAGE_DEBUG_TYPE_CLSID
			|| pddeEntry->Type & IMAGE_DEBUG_TYPE_BORLAND)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "Reserved");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_OMAP_TO_SRC)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "Mapping to an RVA in Source file");
	else if( pddeEntry->Type & IMAGE_DEBUG_TYPE_OMAP_FROM_SRC)	
		strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "Mapping from RVA in Source file");
	else strcpy_s( szDebugEntryType, sizeof szDebugEntryType, "Unrecognized type!");


	time_t tTimeDateStamp = (time_t)pddeEntry->TimeDateStamp;

	const DWORD			dwSize			= g_image_optional_header.DataDirectory[6].Size;
	unsigned short		usBytesToDump	= (unsigned short)(pddeEntry->SizeOfData / 16 + 1) * 16;
	char				*lpDbgInfo		= (char*)( DWORD(g_lpFileMappedOffset )
												+ pddeEntry->PointerToRawData );
	char				*szDump			= (char*)malloc( usBytesToDump * 20 );
	char				szTmp[ 120]		= "";

	memset( szDump, 0, usBytesToDump * 20);

	if( pddeEntry->PointerToRawData > 0x1000 )
	{
		/* Preparing dump of first 128 bytes from Debug informationa (if there are any).
		 * We will use here mine function HexChar which returns dot char or
		 * valid char szDump sended as parameter if it's code is in allowed code area
		 */

		if( usBytesToDump > 128 ) usBytesToDump = 128;

		sprintf( szDump, "\r\n\r\n\tDump of first %d bytes of Debug Informations DATA:\r\n",
				usBytesToDump);

		Dump( (BYTE*)lpDbgInfo, usBytesToDump, szDump, 
				RVAToOffset(g_lpFileMappedOffset, pddeEntry->PointerToRawData) );
	}
	sprintf( lpData,	"\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x07 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
						"DEBUG DIRECTORY ENTRY - Debug informations + minidump\r\n{"
						"\r\n\tCharacteristics:\t\t%X;\r\n\tTimeDateStamp:\t\t%X;\t(%s)"
						"\r\n\tMajorVersion:\t\t%X;\r\n\tMinorVersion:\t\t%X;\r\n\tType:\t\t\t%X;\t"
						"( %s )\r\n\tSizeOfData:\t\t%d bytes;\r\n\tAddressOfRawData:\t%X;"
						"\r\n\tPointerToRawData:\t\t%X;%s\r\n} // Debug Directory Entry\r\n",

						pddeEntry->Characteristics, pddeEntry->TimeDateStamp, ctime(&tTimeDateStamp),
						pddeEntry->MajorVersion, pddeEntry->MinorVersion, pddeEntry->Type, szDebugEntryType,
						pddeEntry->SizeOfData, pddeEntry->AddressOfRawData, pddeEntry->PointerToRawData,
						szDump );
	free( szDump);
	return 1;
}


///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

void DumpDelayLoadIAT ( LPSTR lpData )
{
	if( g_image_optional_header.DataDirectory[13].VirtualAddress == 0
		|| g_image_optional_header.DataDirectory[13].Size == 0 )   return;

	const DWORD	dwSize	= g_image_optional_header.DataDirectory[13].Size;
	const DWORD dwAddr	= g_image_optional_header.DataDirectory[13].VirtualAddress;

	typedef struct _DELAY_LOAD_IMPORT_TABLE 
	{
		DWORD	Attributes;				// Must be zero
		DWORD	Name;					// RVA of the name of the DLL to be loaded
		DWORD	ModuleHandle;			// RVA of the module handle of the DLL to be delay-loaded
		DWORD	DelayIAT;				// RVA of the delay-load import address table 
		DWORD	DelayImportNameTable;	// RVA of the delay-load import names table
		DWORD	BoundDelay;				// The RVA of the bound delay-load address table, if it exists.
		DWORD	UnloadDelay;			// The RVA of the unload delay-load address table
		DWORD	TimeStamp;				// The timestamp of the DLL to which this image has been bound
	} DELAY_LOAD_IMPORT_TABLE, *PDELAY_LOAD_IMPORT_TABLE;

	char szTmp[ 1024] = "";
	char szName[ 64] = "";

	PDELAY_LOAD_IMPORT_TABLE	pDelayLoadIT;
	IMAGE_THUNK_DATA			*pITD, *pITD2;
	IMAGE_IMPORT_BY_NAME		*pIBN;

	sprintf( szTmp, "\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x08 ] -=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
					"Delay-Load Import Table\t( address:  %Xh,    size:  %d bytes )\r\n{\r\n",
					dwAddr, dwSize);
	strcat( lpData, szTmp);

	for( unsigned i = 0; i < ( dwSize / sizeof DELAY_LOAD_IMPORT_TABLE); i++)
	{
		pDelayLoadIT = (PDELAY_LOAD_IMPORT_TABLE)( DWORD(g_lpFileMappedOffset)
										+ sizeof( DELAY_LOAD_IMPORT_TABLE) * i
									+ RVAToOffset(g_lpFileMappedOffset,
									g_image_optional_header.DataDirectory[13].VirtualAddress));

		if( pDelayLoadIT->Name * pDelayLoadIT->ModuleHandle * pDelayLoadIT->DelayIAT 
			* pDelayLoadIT->DelayImportNameTable == 0) break;

		time_t time = (time_t)pDelayLoadIT->TimeStamp;

		DWORD dwNameOffset = DWORD(g_lpFileMappedOffset) 
							+ RVAToOffset(g_lpFileMappedOffset, pDelayLoadIT->Name);
		if( (*((char*)dwNameOffset)) >= 0x30 && (*((char*)dwNameOffset)) <= 'z' )
			strncpy( szName, (char*)dwNameOffset, sizeof szName);
		else strcpy( szName, "Unknown" );

		sprintf_s( szTmp, sizeof szTmp, "\t// ::::::::::::::::::\r\n"
					"\t[%d] Delay-Load Import Table\r\n\t{\r\n\t\t"
					"Attributes:\t\t%d;\r\n\t\tName:\t\t\t\"%s\"\r\n\t\tModule handle:\t\t%X;\r\n\t"
					"\tDelayIAT:\t\t%X;\t\t// (RVA)\r\n\t\tDelayImpNameTable:\t%X;\t\t// (RVA)\r\n"
					"\t\tBoundDelayImpTable:\t%X;\t\t// (RVA)\r\n\t\tUnloadDelayImpTable:\t%X;"
					"\t\t// (RVA)\r\n\t\tTimeStamp:\t\t%X;\t( %s )\r\n"
					"\r\n\t\t #.)\tHint/Ord\tOffset\tAPI Name\r\n"
					"\t\t+------------------------------------------------------+\r\n",

					i, pDelayLoadIT->Attributes, szName, pDelayLoadIT->ModuleHandle,
					pDelayLoadIT->DelayIAT, pDelayLoadIT->DelayImportNameTable, pDelayLoadIT->BoundDelay,
					pDelayLoadIT->UnloadDelay, pDelayLoadIT->TimeStamp, ctime( &time)
		);

		strcat( lpData, szTmp );

		// Iterating on Delay-Load Import thunks
		unsigned uCounter = 0;
		while(true)
		{
			DWORD dwOffset = uCounter++ * IMAGE_SIZEOF_THUNK_DATA;
			DWORD dwMaxValue = DWORD( g_lpFileMappedOffset) + g_dwFileSizeLow;

			pITD = (IMAGE_THUNK_DATA*)( DWORD(g_lpFileMappedOffset) + dwOffset + pDelayLoadIT->DelayIAT);
			pITD2= (IMAGE_THUNK_DATA*)( DWORD(g_lpFileMappedOffset) + dwOffset +
					RVAToOffset( g_lpFileMappedOffset, pDelayLoadIT->DelayImportNameTable ) );
			pIBN = (IMAGE_IMPORT_BY_NAME*)( DWORD(g_lpFileMappedOffset) 
					+ RVAToOffset( g_lpFileMappedOffset, pITD2->u1.AddressOfData));

			if( pITD->u1.Function == 0 || pITD2->u1.AddressOfData == 0 || pIBN->Name == 0
			 || DWORD(pIBN->Name) > dwMaxValue || DWORD(pITD2->u1.AddressOfData) > dwMaxValue) 
				break;

			if( (DWORD(pITD->u1.Ordinal) & IMAGE_ORDINAL_FLAG32) == 0 )
			{
				// Function imported by Name (because  32th bit is not set )

				if( (*((char*)pIBN->Name)) >= 0x30 && (*((char*)pIBN->Name)) <= 'z' )
				 strncpy( szName, (char*)pIBN->Name, sizeof szName);
				else strcpy( szName, "Unknown");

				sprintf_s(	szTmp, sizeof szTmp-1, "\t\t| %d.)\t%X\t%X\t%s\r\n", uCounter-1, 
							pIBN->Hint, dwOffset, szName );
			}else
			{
				// Function imported by a Value (31th bit is set )
				sprintf_s(	szTmp, sizeof szTmp-1, "\t\t| %d.)\t%d\t%X;\t(by Value/Ordinal)\r\n", 
							uCounter-1, DWORD(pITD->u1.Ordinal), dwOffset );
			}

			strcat( lpData, szTmp);
		} // while(true)
		sprintf_s( szTmp, sizeof szTmp -1, 
					"\t\t+------------------------------------------------------+\r\n\r\n"
					"\t\tFunctions imported by this module: %d;\r\n\r\n\t}; "
					"// Imported from %d. module\r\n\r\n",
					uCounter-1, i);
		strcat(lpData, szTmp);

		uCounter = 0;
	}
	strcat( lpData, "} // Delay-Load Import Table\r\n");
}

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

DWORD DumpCertificateInfo( LPSTR lpData)
{
	if( g_image_optional_header.DataDirectory[4].VirtualAddress == 0
		|| g_image_optional_header.DataDirectory[4].Size == 0 )   return 0;

	char	*szTmp, *szTmp2;
	char	szCertTypeDesc[ 64] = "", szRevisionDesc[ 32] = "";
	
	typedef struct _CERTIFICATE_ENTRY {
		DWORD	dwLength;			// Specifies size of bCertificate data
		WORD	wRevision;			// Certificate version number
		WORD	wCertificateType;	// Specifies type of content in bCertificate
		/*char	*bCertificate;*/	// pointer to dynamically allocated buffer, that will contain
									// certificate data, such as an Authenticode signature
	} CERTIFICATE_ENTRY, *PCERTIFICATE_ENTRY;

	PCERTIFICATE_ENTRY	pCertEntry;

	const int ciSizeCertEntryStructMultiplier = 8;			// Specifies size of above structure without 
															// bCertificate member
	const DWORD	dwSizeOfCertTable	= g_image_optional_header.DataDirectory[4].Size;
	const DWORD dwAddrOfCertTable	= g_image_optional_header.DataDirectory[4].VirtualAddress;
	DWORD		dwParsedBytes		= 0;							// Specifies number of bytes parsed from 
																	// DataDirectory[4].VirtualAddress
	unsigned	uCounter			= 0;

	sprintf( lpData, "DUMP OF CERTIFICATE TABLE - Offset in file: 0x%X, Size: %d (%Xh) bytes.\r\n"
			"--------------------------------------------------------------------------------------\r\n",
					dwAddrOfCertTable, dwSizeOfCertTable, dwSizeOfCertTable);
	
	// Loop iterates on all Certificate entries in Certificate Table
	while( dwParsedBytes <= dwSizeOfCertTable )
	{
		pCertEntry	= (PCERTIFICATE_ENTRY)(DWORD(g_lpFileMappedOffset)
					+ dwAddrOfCertTable + dwParsedBytes);			// Computing address of next struct
		
		const unsigned cuSizeOfBuffer = pCertEntry->dwLength * 10 + 128 + 1;
		szTmp = (char*)malloc( cuSizeOfBuffer);						// I know, that in this kind of situations
		szTmp2= (char*)malloc( pCertEntry->dwLength * 10 + 1);		// is better to use realloc function, but
																	// I've decided to not use it.
		if( szTmp == NULL || szTmp2 == NULL) {
			Error( "Heap corruption ! MEMORY LEAK !");
			return 0;
		}
		memset( szTmp, 0, cuSizeOfBuffer);
		memset( szTmp2, 0, pCertEntry->dwLength * 10 + 1);

		if( pCertEntry->wRevision == 0x0100 )
			strcpy( szRevisionDesc, "WIN_CERT_REVISION_1_0");
		else if( pCertEntry->wRevision == 0x0200 )
			strcpy( szRevisionDesc, "WIN_CERT_REVISION_2_0");
		else strcpy( szRevisionDesc, "Unknown revision value");

		if( pCertEntry->wCertificateType == 1 )
			strcpy( szCertTypeDesc, "( X.509 Certificate )");
		else if( pCertEntry->wCertificateType == 2 )
			strcpy( szCertTypeDesc, "( PKCS#7 SignedData structure )");
		else if( pCertEntry->wCertificateType == 3 )
			strcpy( szCertTypeDesc, "( Reserved )");
		else if( pCertEntry->wCertificateType == 4 )
			strcpy( szCertTypeDesc, "\r\n\t\t\t( Terminal Server Protocol Stack Certificate signing )");
		else strcpy( szCertTypeDesc, "( Unknown certificate type )");
		

		// Making dump of bCertificate
		Dump( (LPBYTE)(DWORD(g_lpFileMappedOffset) + dwAddrOfCertTable + dwParsedBytes
				+ ciSizeCertEntryStructMultiplier), pCertEntry->dwLength, szTmp2, 
				(dwAddrOfCertTable + dwParsedBytes + ciSizeCertEntryStructMultiplier), false, 1);

		// Building description of next Certificate entry
		sprintf_s( szTmp, cuSizeOfBuffer, 
					"\r\n[%d]   Certificate entry\taddr:  0x%X  (raw),   size:  %d\r\n{\r\n"
					"\twRevision:\t\t\t%d;\t( %s )\r\n\twCertificateType:\t\t\t%d\t%s\r\n"
					"\tbCertificate - dump of dwLength =\t%d (%Xh) bytes.\r\n%s\r\n\r\n",

					uCounter++, (dwAddrOfCertTable + dwParsedBytes), 
					(pCertEntry->dwLength + ciSizeCertEntryStructMultiplier), 
					pCertEntry->wRevision, szRevisionDesc, pCertEntry->wCertificateType, 
					szCertTypeDesc, pCertEntry->dwLength, pCertEntry->dwLength, szTmp2 );
				
		dwParsedBytes += ciSizeCertEntryStructMultiplier + pCertEntry->dwLength;

		strcat( lpData, szTmp);

		free( (void*)szTmp);
		free( (void*)szTmp2);
	}	
	return 1;
}


///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
// Simple hex-dumping function (it is really slow). 
//	Parameters: 
//		+	_lpAddressOfData	- address of memory block with data to dump, 
//		+	llSize				- number of bytes to dump, 
//		+	szBuffer			- buffer where to write dump cstring,
//		+	dwRelativeOffset	- specifies from what offset to start numering lines,
//		+	bWideMode			- specifies wheter to use wide print format (wide cstrings), 
//		+	uTabulators			- number of tabulators to use before each line,

VOID Dump(	LPBYTE _lpAddressOfData, long long llSize, 
			LPSTR szBuffer, DWORD dwRelativeOffset, BOOL bWideMode, SHORT sTabulators )
{
	char	szTmp[ 180]		= "";
	char	szTabs[6]		= "";
	char	szSpaces[ 12]	= "";
	char	szFormat[ 180]	= "";
	char	szLine[ 100]	= "";

	register LPBYTE	lpAddressOfData = _lpAddressOfData;

	if( bWideMode)
		 strcpy_s( szLine, sizeof szLine,	"------------+-----------------------------"
											"----------------------------------------+");
	else strcpy_s( szLine, sizeof szLine,
				"--------+--------------------------------------------------------------------------+");

	typedef unsigned char _byte;

	if( sTabulators > 0 && sTabulators < sizeof szTabs)
	{
		memset( szTabs, '\0', sizeof szTabs);
		memset( szTabs, '\t', sTabulators);
	}
	
	if( bWideMode == FALSE )
	{
		sprintf_s(	szTmp, sizeof szTmp, 
					"\r\n%s\t00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\r\n%s%s\r\n", 
					szTabs, szTabs, szLine );
		strcat(		szBuffer, szTmp);
		strcpy_s( szFormat, sizeof szFormat,
							"%s%X%s |   %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X "
							"%.2X %.2X %.2X %.2X %.2X %.2X     \t|   %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\r\n" );
	}else{ 
		sprintf_s(	szTmp, sizeof szTmp, 
					"\r\n%s\t         00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F\r\n%s%s\r\n", 
					szTabs, szTabs, szLine );
		strcat(		szBuffer, szTmp);
		strcpy_s( szFormat,	 sizeof szFormat,
							"%s%X%s |      %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  "
							"%.2X  %.2X  %.2X  %.2X  %.2X  %.2X\t|   %.2c%.2c%.2c%.2c%.2c"
							"%.2c%.2c%.2c%.2c%.2c%.2c%.2c%.2c%.2c%.2c%.2c\r\n" );
	}

	// One loop dumps 16 bytes at once
	for(unsigned i = 0; i < llSize; i += 16 )
	{
		if( bWideMode) strcpy( szSpaces, "\t");
		else if( !bWideMode && ( 0 == (i % 0x10) ) )
		{
					if( dwRelativeOffset+i == 0)		strcpy( szSpaces, "        ");
			else	if( dwRelativeOffset+i < 0x100)		strcpy( szSpaces, "      ");
			else	if( dwRelativeOffset+i < 0x1000)	strcpy( szSpaces, "    ");
			else	if( dwRelativeOffset+i < 0x10000)	strcpy( szSpaces, "  ");
			else										strcpy( szSpaces, " ");
		}

		sprintf_s(	szTmp, sizeof(szTmp)-1, szFormat, szTabs, dwRelativeOffset+i, szSpaces,
					_byte(lpAddressOfData[i]),    _byte(lpAddressOfData[i+1]),  _byte(lpAddressOfData[i+2]), 
					_byte(lpAddressOfData[i+3]),  _byte(lpAddressOfData[i+4]),  _byte(lpAddressOfData[i+5]), 
					_byte(lpAddressOfData[i+6]),  _byte(lpAddressOfData[i+7]),  _byte(lpAddressOfData[i+8]), 
					_byte(lpAddressOfData[i+9]),  _byte(lpAddressOfData[i+10]), _byte(lpAddressOfData[i+11]), 
					_byte(lpAddressOfData[i+12]), _byte(lpAddressOfData[i+13]), _byte(lpAddressOfData[i+14]), 
					_byte(lpAddressOfData[i+15]), 

					HexChar(lpAddressOfData[i+0]),  HexChar(lpAddressOfData[i+1]),
					HexChar(lpAddressOfData[i+2]),  HexChar(lpAddressOfData[i+3]),
					HexChar(lpAddressOfData[i+4]),  HexChar(lpAddressOfData[i+5]),
					HexChar(lpAddressOfData[i+6]),  HexChar(lpAddressOfData[i+7]),
					HexChar(lpAddressOfData[i+8]),  HexChar(lpAddressOfData[i+9]),
					HexChar(lpAddressOfData[i+10]), HexChar(lpAddressOfData[i+11]),
					HexChar(lpAddressOfData[i+12]), HexChar(lpAddressOfData[i+13]),
					HexChar(lpAddressOfData[i+14]), HexChar(lpAddressOfData[i+15])
		);
		strcat(szBuffer, szTmp);
	}
	sprintf_s( szTmp, sizeof szTmp, "%s%s\r\n", szTabs, szLine);
	strcat( szBuffer, szTmp);
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This functions examine sended as parameter char code, and returns it or dot code

inline char HexChar(int c)
{
	if( c >= 0x20 && c <= 0x7D)return (char)c;
	//if( isprint( c) ) return (char)c;
	//if( c > 0x1F && c != 0x7F && c != 0x81 && c < 0xFF) return (char)c;
	else return '.';
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
