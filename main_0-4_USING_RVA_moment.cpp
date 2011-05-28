
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

#include "resource.h"

// #pragma data_seg( "PEInfoD")
// #pragma code_seg( "PEInfoC")

#pragma warning(disable: 4996)

// This constant will tell when to convert RVA to Offset
// and when do not do it (and use RVA as Offset).
// Used in List_IAT and List_EAT.
#define USING_RVA	1

#define IMAGE_SIZEOF_IMPORT_DESCRIPTOR 20
#define IMAGE_SIZEOF_THUNK_DATA 4
#define IMAGE_SIZEOF_IMPORT_BY_NAME 3
#define IMAGE_SIZEOF_DOS_HEADER 64
#define IMAGE_SIZEOF_DOS_STUB 64
#define IMAGE_SIZEOF_OPTIONAL_HEADER 248
#define IMAGE_SIZEOF_SECTION_HEADER 40
#define IMAGE_SIZEOF_EXPORT_DIRECTORY 40

using namespace std;


/* /////////////////////// F U N C T I O N S  D E C L A R A T I O N S ////////////////////// */

BOOL CALLBACK	 	MainWindowProcedure (HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK		EditValueDialogProcedure ( HWND, UINT, WPARAM, LPARAM);

BOOL				CollectInformations (LPSTR szFilePath );

VOID				__Error(char szInfo[], DWORD dwErrno, DWORD dwLine, char szFunction[] );
#define				Error(x) __Error(x, GetLastError(), __LINE__, __FUNCTION__ )

BOOL				ReadBytes( HANDLE hFile, LPVOID lpBuffer, DWORD dwBufferSize );
BOOL				WriteBytes( HANDLE hFile, LPCVOID lpBuffer, DWORD dwBufferSize );
UINT WINAPI			DumpPEInfoToDlg( void* lParam );
char				HexChar(int c);
VOID				FillSecondCombo(DWORD dwSelected);
VOID				OnCommand_EditValueDialog(WPARAM, LPARAM);
BOOL				SaveHeadersToFile();
DWORD				List_IAT(char *, int iSize);
DWORD				List_EAT(char *szLog, int iBufSize);
DWORD				_RVAToOffset ( const DWORD pFileMap, /* const */ DWORD dwRVA );
#define				RVAToOffset(x,y) _RVAToOffset((DWORD)x, y)


/* ////////////////////////// G L O B A L  V A R I A B L E S /////////////////////////////// */
		
HWND		g_hMain, g_hEditValueDialog;
HINSTANCE	g_hInstance;

bool		g_bActive = true;
#if _DEBUG
	bool		g_bTopMost = false;
#else
	bool		g_bTopMost = true;
#endif

HANDLE		g_hDumpPEThread = INVALID_HANDLE_VALUE;

char					g_szFilePath[MAX_PATH+1];
IMAGE_DOS_HEADER		g_image_dos_header; 
unsigned char			g_DOS_STUB[64];
ULONG					g_ulNT_Signature;
IMAGE_FILE_HEADER		g_image_file_header;
IMAGE_OPTIONAL_HEADER	g_image_optional_header;
IMAGE_SECTION_HEADER	g_image_section_header[8];

DWORD		g_dwCollectingTime		= 0, 
			g_dwPreparingLogTime	= 0, 
			g_dwReadingIATTime		= 0,
			g_dwReadingEATTime		= 0;

LPVOID		g_lpFileMappedOffset	= 0;


/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* ///////////////////////////////////////////////////////////////////////////////////////// */
/* /////////////////////		 W I N M A I N   	 /////////////////////////////////////// */

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nMode)
{
	

	g_hInstance = hInstance;  

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

	/* ------------------------------------------------------------------------------------- */    
	g_hMain = CreateDialogA( hInstance, (LPCSTR)IDD_DIALOG1, HWND_DESKTOP, MainWindowProcedure);
	SendMessageA(GetDlgItem(g_hMain, IDC_EDIT2), EM_LIMITTEXT, (WPARAM)15, 0);

#if _DEBUG
	SetWindowTextA(g_hMain, "PEInfo v0.4 (DEBUG)");
#endif

	DragAcceptFiles( g_hMain, TRUE);

	RECT rc;
	CheckDlgButton(g_hMain, IDC_CHECK1, g_bTopMost? BST_CHECKED : BST_UNCHECKED);
	GetWindowRect(g_hMain, &rc);
	SetWindowPos(g_hMain, g_bTopMost? HWND_TOPMOST : HWND_NOTOPMOST, rc.left, rc.top, 
					rc.right-rc.left, rc.bottom-rc.top, SWP_SHOWWINDOW);

    /* Make the window visible on the screen */
    ShowWindow ( g_hMain, nMode );
    UpdateWindow ( g_hMain );

	MSG msgMessages;
    
	/* ------------------------------------------------------------------------------------- */
    /* Run the message loop. Loop is of course infinitve. */
    for(;;)
	{
		
		if( PeekMessage ( &msgMessages, g_hMain, 0, 0, PM_REMOVE ) != FALSE
			&& ! IsDialogMessageA(g_hEditValueDialog, &msgMessages)
		){	/* There is an message to dispatch */ 
    		
        	TranslateMessage 	( &msgMessages );
       		DispatchMessage 	( &msgMessages );
       		
		}
    		
    } /* for(;;) */

	/* ------------------------------------------------------------------------------------- */
	
	TerminateThread(g_hDumpPEThread, 0);
	CloseHandle(g_hDumpPEThread);
	g_hDumpPEThread = INVALID_HANDLE_VALUE;

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

			if(dwCtrlID == IDC_BUTTON1 )
			{
				OPENFILENAMEA ofn;
				ZeroMemory(&ofn, sizeof(ofn) );
				char szTmp[100] = "";

				ofn.lStructSize		= sizeof( OPENFILENAMEA);
				ofn.Flags			= OFN_FILEMUSTEXIST | OFN_NONETWORKBUTTON;
				ofn.hInstance		= g_hInstance;
				ofn.hwndOwner		= hDlg;
				ofn.lpstrFilter		=	"All Valid PE Files (*.exe;*.dll;*.obj;*.lib;*.com)\0*.exe;*.dll;*.obj;*.lib;*.com\0"
										"PE Executables (*.exe)\0*.exe\0PE Dynamic Link Libraries (*.dll)\0*.dll\0"
										"Semi-PE Object Files (*.obj)\0*.obj\0PE Static Libraries (*.lib)\0*.lib\0"
										"Old DOS Executables (*.com)\0*.com\0All Files (*.*)\0*.*\0";
				ofn.lpstrDefExt		= "exe";
				ofn.nMaxFile		= MAX_PATH;
				ofn.lpstrFile		= szTmp;

				if(!GetOpenFileNameA(&ofn) || CommDlgExtendedError() || GetLastError() )
				{
					char szError[64] = "";
					sprintf_s(szError, sizeof(szError)-1, "Error while typing file. GetOpenFileNameA failed. (%s() )",
							(GetLastError()? "GLE" : "CDEE"));
					__Error(szError, ((CommDlgExtendedError() )? CommDlgExtendedError() : GetLastError() ), 
							__LINE__, __FUNCTION__);
					break;	
				}

				strncpy_s(g_szFilePath, sizeof(g_szFilePath)-1, szTmp, strlen(szTmp));
				ZeroMemory(szTmp, 100);
				if(strlen(g_szFilePath) < 80)
					sprintf_s(szTmp, sizeof(szTmp)-1, "PEInfo v0.4 - \"%s\"", g_szFilePath);
				else sprintf_s(szTmp, sizeof(szTmp)-1, "PEInfo v0.4 - \"%s\"", 
						(char*)strrchr((const char*)g_szFilePath, (int)'\\')+1);
				
				SetWindowTextA(hDlg, szTmp);
				SetWindowTextA(GetDlgItem(hDlg, IDC_FILEPATH), g_szFilePath);

				// Mapping file to the memory
				{

					HANDLE hFile, hMap;
					DWORD dwSizeLow, dwSizeHigh;

					hFile = CreateFileA(g_szFilePath, GENERIC_READ, 
										FILE_SHARE_READ, NULL, 
										OPEN_EXISTING, 0, NULL );
					if( hFile == INVALID_HANDLE_VALUE || GetLastError() )
					{
						char szTmp2[56] = "";
						sprintf_s(szTmp2, sizeof(szTmp2)-1, "Cannot open file to map !");
						Error( szTmp2);
						break;
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
						break;
					}

					// Mapping file in process (PEInfo.exe) memory.
					g_lpFileMappedOffset = MapViewOfFile (hMap, FILE_MAP_READ, 0, 0, 0);
					if( g_lpFileMappedOffset == NULL || GetLastError() )
					{
						CloseHandle( hMap );
						CloseHandle( hFile );

						char szTmp2[56] = "";
						sprintf_s(szTmp2, sizeof(szTmp2)-1, "Cannot map view of file !");
						Error( szTmp2);
						break;
					}

					CloseHandle(hFile );
					CloseHandle( hMap );

				}
				CollectInformations( g_szFilePath);

				EnableWindow(GetDlgItem(hDlg, IDC_BUTTON5), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDC_BUTTON6), TRUE);

			}else if( dwCtrlID == IDOK) SendMessageA( hDlg, WM_CLOSE, 0, 0);
			else if( dwCtrlID == IDC_CHECK1 )
			{
				g_bTopMost = !g_bTopMost;
				CheckDlgButton(hDlg, IDC_CHECK1, (!g_bTopMost)? BST_UNCHECKED : BST_CHECKED );
				RECT rc;
				GetWindowRect(hDlg, &rc);
				SetWindowPos(hDlg, (!g_bTopMost)? HWND_NOTOPMOST : HWND_TOPMOST, 
								rc.left, rc.top, rc.right-rc.left, rc.bottom-rc.top, SWP_SHOWWINDOW);
			}else if( dwCtrlID == IDC_BUTTON2)
			{
				char szAbout[128+1] = "";
				sprintf_s(szAbout, sizeof(szAbout)-1, "PEInfo v0.4, coded by MGeeky #2009\r\nLicense: GPL\r\n\r\n"
					"Any informations or questions send to timpler[at]o2[dot]pl");

				MessageBoxA(NULL, szAbout, "About PEInfo...", MB_ICONINFORMATION);

			}else if(dwCtrlID == IDC_CHECK2)
			{
				BOOL bVisible = IsWindowVisible(GetDlgItem(hDlg, IDC_EDIT2) );

				ShowWindow(GetDlgItem(hDlg, IDC_EDIT2),		bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON3),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON4),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON5),	bVisible? SW_HIDE : SW_SHOW);
				ShowWindow(GetDlgItem(hDlg, IDC_BUTTON6),	bVisible? SW_HIDE : SW_SHOW);

			}
			else if( dwCtrlID == IDC_BUTTON3)
			{
				char szValue[16] = "";
				long lValue;
				GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
				if( strlen( szValue) < 1) break;

				lValue = atol(szValue);
				sprintf_s(szValue, sizeof(szValue)-1, "%X", lValue);

				SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

			}else if( dwCtrlID == IDC_BUTTON4)
			{
				char szValue[16] = "";
				long lValue;
				GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
				if( strlen( szValue) < 1) break;

				lValue = strtol(szValue, NULL, 16);
				sprintf_s(szValue, sizeof(szValue)-1, "%d", lValue);

				SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

			}else if( dwCtrlID == IDC_BUTTON5 )
			{
				DialogBoxA(g_hInstance, (LPCSTR)IDD_DIALOG2, 
							hDlg, EditValueDialogProcedure);

				ShowWindow(g_hEditValueDialog, SW_SHOW);

			}else if( dwCtrlID == IDC_BUTTON6 )
			{
				char szValue[16] = "";				
				long lValue;
				static bool bDisplayed = false;

				GetDlgItemTextA(hDlg, IDC_EDIT2, szValue, sizeof(szValue)-1);
				if( strlen( szValue) < 2 && bDisplayed == false)
				{
					MessageBoxA(NULL,	"About \"RVA2Offset\" function...\r\n\r\n\"RVA2Offset\" is function"
										"which converts typed RVA into offset in THIS (!!) file."
										"\r\nSo type HEXADECIMAL Relative Virtual Address and click this button"
										", and function will convert value.\r\n\r\nThis INFO won't display once again"
										" unless you reset application.", "About RVA2Offset", MB_ICONINFORMATION);
					bDisplayed = true;
					break;
				}

				lValue = strtol(szValue, NULL, 16);
				if( lValue == LONG(g_lpFileMappedOffset)) break;
				
				sprintf_s(szValue, sizeof(szValue)-1, "%X", RVAToOffset(g_lpFileMappedOffset, lValue));
				SetDlgItemTextA(hDlg, IDC_EDIT2, szValue);

			}


		}break;
				
		/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
		case WM_DROPFILES:
		{
			char szTmp[MAX_PATH+1] = "";
			HDROP hDrop = (HDROP)wParam;
			DragQueryFileA(hDrop, 0, g_szFilePath, MAX_PATH);
			DragFinish(hDrop);

			sprintf_s(szTmp, sizeof(szTmp)-1, "PEInfo v0.4 - \"%s\"", g_szFilePath);
			
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
			if( LOWORD(wParam) == IDC_RADIO1 || LOWORD(wParam) == IDC_RADIO2 || LOWORD(wParam) == IDC_RADIO3)
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
		case WM_ACTIVATE:
		{	g_bActive = ( (LOWORD(wParam) == WA_ACTIVE)? true : false );
				
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
/* /////////////////		F U N C T I O N S  D E F I N I T I O N S		//////////////// */


// This procedure prepares log about application error

VOID __Error(char szInfo[], DWORD dwErrno, DWORD dwLine, char szFunction[] )
{

	if(dwErrno == 0) return;

	char *szError = (char*)malloc(300);
	
	sprintf_s(szError, 299, "Application has caught an unhandled exception.\r\n\r\n"
		"Error code:\t%d\r\nAt line:\t\t%d\r\nIn function:\t%s()\r\nError:\t\t%s\r\n\r\n\r\n"
					 "[?] Do You want to terminate application?", dwErrno, dwLine, szFunction, szInfo);

	if(MessageBoxA(NULL, szError, "PEInfo Error", 
					MB_ICONERROR|MB_APPLMODAL|MB_TASKMODAL|MB_YESNO|MB_DEFBUTTON2) == IDYES)
	{
		ShowWindow(g_hMain, SW_HIDE);
		DestroyWindow ( g_hMain );
		g_hMain = 0;
		free((void*)szError);
		TerminateThread(g_hDumpPEThread, 0);
		CloseHandle(g_hDumpPEThread);
		g_hDumpPEThread = INVALID_HANDLE_VALUE;

		ExitProcess(0);
	}

	free((void*)szError);
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// Function loads file, and read from it PE Headers.

BOOL CollectInformations (LPSTR szFilePath )
{
	DWORD dwStart = GetTickCount();

	/* -------------------------- Variables ------ */
	DWORD dwBytes = 0;
	DWORD nOffset;
	
	ULONG ul_NT_Signature = 0;

	HANDLE hFile;

	IMAGE_DOS_HEADER image_dos_header;
	IMAGE_FILE_HEADER image_file_header;
	IMAGE_OPTIONAL_HEADER32 image_optional_header;
	IMAGE_SECTION_HEADER image_section_header;

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

	/* Read IMAGE_DOS_HEADER */
	ReadBytes(hFile, (LPVOID)&image_dos_header, sizeof(IMAGE_DOS_HEADER) );
	if( IMAGE_DOS_SIGNATURE != image_dos_header.e_magic || GetLastError() )
	{
		Error( "This is not valid file. It cannot be parsed by PEInfo.");
		return FALSE;
	}

	/*for( int i = 0; i < 63; i++)
	{
		char c = 0;
		ReadFile(hFile, &c, 1, NULL, NULL);
		if( !hFile || GetLastError() )
		{
			char szError[64] = "";
			sprintf(szError,  "Error while reading DOS_STUB (iteration: %d) !", i );
			Error( szError );
			break;
		}
		
		g_DOS_STUB[i] = c;
	}
	g_DOS_STUB[64] = '\0';
	*/

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
	
	// Actual File Offset: 0x00000178

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
	g_dwCollectingTime = GetTickCount() - dwStart;

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

BOOL WriteBytes( HANDLE hFile, LPCVOID lpBuffer, DWORD dwBufferSize )
{
	DWORD dwBytes = 0;
	static unsigned uWriteCounter = 0;

	if( ! WriteFile( hFile, (LPVOID)lpBuffer, dwBufferSize, &dwBytes, NULL) || GetLastError()  )
	{
		Error( "Error while reading file !" );
		return FALSE;
	}
	uWriteCounter++;

	if( dwBufferSize != dwBytes || GetLastError()  )
	{
		char szInfo[64] = "";
		sprintf_s(szInfo, sizeof(szInfo), " Written wrong number of bytes ! Expected %lu, got %lu. (at: %X)", 
				dwBufferSize, dwBytes, uWriteCounter);
		Error( szInfo);
		return FALSE;
	}
	
	return TRUE;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
// RVAToOffset procedure (converts Relatives to absolute offset), by MGeeky

DWORD _RVAToOffset ( const DWORD pFileMap, DWORD dwRVA )
{
	DWORD dwTmp = 0;
	
	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)pFileMap;
	PIMAGE_NT_HEADERS inthdr = (PIMAGE_NT_HEADERS)DWORD(pFileMap + idh->e_lfanew);
	PIMAGE_FILE_HEADER ifh = (PIMAGE_FILE_HEADER)DWORD( pFileMap + idh->e_lfanew + 4 );
	
	DWORD dwOffset = (DWORD)(pFileMap + 0x00000178 );
	PIMAGE_SECTION_HEADER ish = (PIMAGE_SECTION_HEADER)dwOffset;
	
	DWORD dwNumOfSections = ifh->NumberOfSections;
	
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
	DWORD dwStart = GetTickCount();

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

	char		szTmp[1024]				= "";
	char		szName[128]				= "";

	LPVOID		lpBuffer				= g_lpFileMappedOffset;
	time_t		tTimeDateStamp;

	/* -------------------------- Variables -------------------------- */

	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)g_lpFileMappedOffset;

	dwOffset = (DWORD)g_lpFileMappedOffset + idh->e_lfanew+ 4 + IMAGE_SIZEOF_FILE_HEADER;
	ioh = ((PIMAGE_OPTIONAL_HEADER)( dwOffset));

	// Getting offset to the first IMAGE_IMPORT_DESCRIPTOR structure and size of import table
#if USING_RVA == 1
	dwImpSectionVA = RVAToOffset(lpBuffer, ioh->DataDirectory[1].VirtualAddress);
#else
	dwImpSectionVA = ioh->DataDirectory[1].VirtualAddress;
#endif
	dwImpSectionSize = ioh->DataDirectory[1].Size;

	// Iterating all imported modules and its exported functions
	for( int i = 0; ; i++)
	{
		ZeroMemory(szTmp, sizeof(szTmp) );

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
#if USING_RVA == 1
		dwOffset = RVAToOffset(g_lpFileMappedOffset, image_import_descriptor->Name);
#else
		dwOffset = image_import_descriptor->Name;
#endif
		dwOffset += (DWORD)lpBuffer;

		// Preparing name of imported module.
		if( dwOffset != NULL && strlen((const char*)dwOffset) > 0)
		{
			strncpy_s(	szName, sizeof(szName)-1, (const char*)dwOffset, strlen((const char*)dwOffset) );
		}else strcpy_s(	szName, sizeof(szName)-1, "Unknown");

		sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n\tIMAGE_IMPORT_DESCRIPTOR[%d]\r\n\t{\r\n\t\tOriginalFirstThunk:\t\t%X;\r\n"
						"\t\tTimeDateStamp:\t\t%X;", i, image_import_descriptor->OriginalFirstThunk, 
						image_import_descriptor->TimeDateStamp );

		if( image_import_descriptor->TimeDateStamp != 0)
		{
			tTimeDateStamp = (time_t)image_import_descriptor->TimeDateStamp;
			sprintf_s( szTmp, sizeof(szTmp)-1, "%s\r\n\t\t\t\t\t( %s )", szTmp, ctime( &tTimeDateStamp) );
		}
						
		sprintf_s(szTmp, sizeof(szTmp)-1, "%s\r\n\t\tForwarderChain:\t\t%X;\r\n\t\tName:\t\t\t\"%s\";\r"
						"\n\t\tFirstThunk:\t\t%X;\r\n\r\n"
						"\t\tOffset of this descriptor:\t%X;\r\n\r\n"
						"\r\n\t\t #.)\tHint\tOffset\tAPI Name\r\n"
						"\t\t+------------------------------------------------------+\r\n", 
						szTmp, image_import_descriptor->ForwarderChain, szName, image_import_descriptor->FirstThunk,
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
				return 0xFFFF;
			}

			// Getting access to thunk RVA
			dwOffset = DWORD(g_lpFileMappedOffset) + (f * IMAGE_SIZEOF_THUNK_DATA);;
		#if USING_RVA == 1
			dwOffset += RVAToOffset(lpBuffer, image_import_descriptor->OriginalFirstThunk);
		#else
			dwOffset += image_import_descriptor->OriginalFirstThunk;
		#endif

			image_thunk_data = (PIMAGE_THUNK_DATA)( dwOffset);

			if( image_thunk_data->u1.Function == NULL ) break;
			
			ZeroMemory(szTmp, sizeof(szTmp) );

			if( !(DWORD(image_thunk_data) & IMAGE_ORDINAL_FLAG32) )
			{
				// Function imported by Name (because  31th bit is not set )
			#if USING_RVA == 1
				dwOffset = ( DWORD(lpBuffer) + RVAToOffset(lpBuffer, image_thunk_data->u1.Function) );
			#else
				dwOffset = ( DWORD(lpBuffer) + image_thunk_data->u1.Function );
			#endif
				image_import_by_name = (PIMAGE_IMPORT_BY_NAME)( dwOffset);

				int i = 0, iLastAlnum = 0;
				bool bBreaked = false;
				while( ( image_import_by_name->Name[i] != '\0') && ++i && ++iLastAlnum && !bBreaked )
					if( i >= 60 ) bBreaked = true;
					else if( isprint( image_import_by_name->Name[i]) == FALSE) bBreaked = true;

				if( bBreaked) 
				{
					strncpy_s( szName, sizeof( szName)- 1, (const char*)image_import_by_name->Name, iLastAlnum);
					szName[iLastAlnum+1] = '\0';
				}else strcpy_s( szName, sizeof( szName)- 1, (const char*)image_import_by_name->Name);


				sprintf_s(szTmp, sizeof(szTmp)-1, "\t\t| %d.)\t%X\t%X\t%s\r\n", f, 
							image_import_by_name->Hint, (dwOffset-DWORD(g_lpFileMappedOffset)),szName  );
			}else
			{
				// Function imported by a Value (31th bit is set )
				sprintf_s(szTmp, sizeof(szTmp)-1, "\t\t%d.)\tFunction Imported by Value\t%d\t%X;\r\n", 
							f, (DWORD(image_thunk_data) & 0x0FFFF), dwOffset );
			}

			if(szLog != NULL) strcat_s( szLog, iBufSize-1, szTmp);		

			++f;

		} // while( true)

		if(szLog != NULL) 
		{
			sprintf_s( szTmp, sizeof( szTmp) -1, 
						"\t\t+------------------------------------------------------+\r\n\r\n"
						"\t\tFunctions imported by this module: %d;\r\n\r\n\t}; // Imported from %d. module\r\n\r\n",
						f, i);
			strcat_s(szLog, iBufSize-1, szTmp);

			dwImportedFunctions += f;
		}

	} // for( int i = 0; ; i++)

	ZeroMemory(szTmp, sizeof(szTmp) -1);
	sprintf(szTmp, "\r\n\r\n\tAll imported functions by this application:\t%d;", dwImportedFunctions);
	strcat_s(szLog, iBufSize, szTmp);
	
	g_dwReadingIATTime = GetTickCount() - dwStart;

	return 0;
}




/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function list all EAT (Export Address Table) entries.

DWORD List_EAT(char *szLog, int iBufSize)
{
	DWORD dwStart = GetTickCount();

	/* -------------------------- Variables -------------------------- */
	PIMAGE_EXPORT_DIRECTORY		image_export_directory;
	PIMAGE_OPTIONAL_HEADER		ioh;

	DWORD		nOffset = 0, dwOffset = 0;
	DWORD		dwSizeLow = 0,
				dwSizeHigh = 0;
	
	DWORD		dwExpSectionVA, dwExpSectionSize;
	LPVOID		lpOffset = 0;
	LPVOID		lpBuffer = g_lpFileMappedOffset;

	char szTmp[1024] = "";
	char szName[128] = "";

	/* -------------------------- Variables -------------------------- */

	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)lpBuffer;

	dwOffset = (DWORD)lpBuffer + idh->e_lfanew+ 4 + IMAGE_SIZEOF_FILE_HEADER;
	ioh = ((PIMAGE_OPTIONAL_HEADER)( dwOffset));

	// Getting offset to the first IMAGE_IMPORT_DESCRIPTOR structure and size of import table
#if USING_RVA == 1
	dwExpSectionVA = RVAToOffset(lpBuffer, ioh->DataDirectory[0].VirtualAddress);
#else
	dwExpSectionVA = ioh->DataDirectory[0].VirtualAddress;
#endif
	dwExpSectionSize = ioh->DataDirectory[0].Size;

	ZeroMemory(szTmp, sizeof(szTmp) );

	if( strlen( szLog) >= unsigned(iBufSize - 200) || GetLastError()  )
	{
		Error( "Buffer is too small to carry all informations about Export Table !");
		return 0xFFFF;
	}

	// Now we taking access to IMAGE_EXPORT_DIRECTORY
	dwOffset = DWORD(lpBuffer) + dwExpSectionVA;
	image_export_directory = (PIMAGE_EXPORT_DIRECTORY)( dwOffset);

	if( image_export_directory->AddressOfFunctions == NULL &&
		image_export_directory->AddressOfNameOrdinals == NULL &&
		image_export_directory->AddressOfNames == NULL &&
		image_export_directory->Name == NULL)
		return 0xFFFF;

	// Computing offset of a module name
#if USING_RVA == 1
	dwOffset = RVAToOffset(lpBuffer, image_export_directory->Name);
#else
	dwOffset = image_export_directory->Name;
#endif
	dwOffset += (DWORD)lpBuffer;

	// Preparing name of exported module.
	if( dwOffset != NULL && strlen((const char*)dwOffset) > 0)
	{
		strncpy_s(	szName, sizeof(szName)-1, (const char*)dwOffset, strlen((const char*)dwOffset) );
	}else strcpy_s(	szName, sizeof(szName)-1, "Unknown");

	sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n\tIMAGE_EXPORT_DIRECTORY\r\n\t{\r\n\t\t"
					"Characteristics:\t\t%X;\r\n\t\tTimeDateStamp:\t\t%X;", 
					image_export_directory->Characteristics, image_export_directory->TimeDateStamp );
					
	if( image_export_directory->TimeDateStamp != 0)
	{
		time_t tTimeDateStamp = (time_t)image_export_directory->TimeDateStamp;
		sprintf_s( szTmp, sizeof(szTmp)-1, "%s\r\n\t\t\t\t\t( %s )", szTmp, ctime( &tTimeDateStamp) );
	}
					
	sprintf_s(szTmp, sizeof(szTmp)-1, "%s\r\n\t\tMajorVersion:\t\t%X;\r\n\t\tMinorVersion:\t\t%X;\r"
					"\n\t\tnName:\t\t\t\"%s\";\r\n\t\tnBase:\t\t\t%X;\r\n\t\tNumberOfFunctions:\t%X;"
					"\r\n\t\tNumberOfNames:\t\t%X;\r\n\t\tAddressOfFunctions:\t%X;\r\n\t\tAddressOfNames:\t"
					"\t%X;\r\n\t\tAddressOfNameOrdinals:\t%X;\r\n"
					"\r\n\t\tOffset of this export directory:\t%X;\r\n\r\n"
					"\r\n\t\t #.)\tOrdinal\tRVA\tAPI Name\r\n"
					"\t\t+-----------------------------------------------------------------+\r\n", 
					szTmp, image_export_directory->MajorVersion, image_export_directory->MinorVersion, 
					szName, image_export_directory->Base, image_export_directory->NumberOfFunctions,
					image_export_directory->NumberOfNames, image_export_directory->AddressOfFunctions,
					image_export_directory->AddressOfNames, image_export_directory->AddressOfNameOrdinals,
					dwExpSectionVA
	);

	if(szLog != NULL) strcat_s(szLog, iBufSize-1, szTmp);

	int		f			= 0;
	DWORD	dwOrdinal	= 0,
			dwRVA		= 0, 
			dwNameRVA	= 0;

#if USING_RVA == 1
	dwRVA		= RVAToOffset(lpBuffer, image_export_directory->AddressOfFunctions  );
	dwOrdinal	= RVAToOffset(lpBuffer, image_export_directory->AddressOfNameOrdinals );
#else
	dwRVA		= image_export_directory->AddressOfFunctions;
	dwOrdinal	= image_export_directory->AddressOfNameOrdinals;
#endif

	// Iterating all exported functions from this module
	for(f = 0; unsigned(f) < image_export_directory->NumberOfFunctions; f++)
	{
		if( strlen( szLog) >= unsigned(iBufSize - 30) || GetLastError()  )
		{
			Error( "Buffer is too small to carry all informations about Export Table Entries !");
			break;
		}

		// Computing offset to API function name
		dwOffset = DWORD(lpBuffer) + ( f * sizeof(DWORD) );

	#if USING_RVA == 1
		dwOffset += RVAToOffset(lpBuffer, image_export_directory->AddressOfNames  );
		dwNameRVA = DWORD(lpBuffer) + RVAToOffset(lpBuffer, DWORD(*((DWORD*)dwOffset) ) );
	#else
		dwOffset += image_export_directory->AddressOfNames;
		dwNameRVA = DWORD(lpBuffer) + DWORD(*((DWORD*)dwOffset));
	#endif

		ZeroMemory(szTmp, sizeof(szTmp) );
		ZeroMemory(szName, sizeof(szName));

		strcpy_s(szName, sizeof(szName)-1, (const char*)(dwNameRVA) );
		sprintf_s(szTmp, sizeof(szTmp)-1, "\t\t| %d.)\t%d\t%X\t%s\r\n", f, 
					dwOrdinal+f*2, dwRVA+f*4, szName  );

		if(szLog != NULL) strcat_s( szLog, iBufSize-1, szTmp);

	} // for(f = 0; unsigned(f) < image_export_directory->NumberOfFunctions; f++)

	if(szLog != NULL) 
	{
		sprintf_s( szTmp, sizeof( szTmp) -1, 
					"\t\t+-----------------------------------------------------------------+\r\n\r\n"
					"\t\tFunctions exported by this module: %d;\r\n\r\n\t}; // Exported\r\n\r\n",
					f);
		strcat_s(szLog, iBufSize-1, szTmp);
	}

	g_dwReadingEATTime = GetTickCount() - dwStart;

	return 0;
}



/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This function prepares a log about selected file and prints it.

UINT WINAPI DumpPEInfoToDlg( void* lParam )
{

	// This function prepares and shows log of analyzed file.
	DWORD dwStart = GetTickCount();

	/* ------------------------------- Variables ----------------- */
	HWND hwnd										= (HWND)lParam;

	DWORD dwOffset									= 0;

#ifdef _DEBUG
	const DWORD dwDumpedPESize						= 16384;
#else
	const DWORD dwDumpedPESize						= 65536;
#endif

	const DWORD dwTmpSize							= 2048;

	char *szDumpedPE								= (char*)malloc(dwDumpedPESize);
	char szTmp[dwTmpSize]							= "",
		 szTmp2[dwTmpSize]							= "";

	IMAGE_SECTION_HEADER *pImage_section_header		= NULL;
	/* ----------------------------------------------------------- */

	/* Check if while allocating memory occured a memory leak */
	if( ! szDumpedPE || GetLastError() || dwDumpedPESize < 10 )
	{
		char szError[ 64] = "";
		sprintf( szError, "Cannot alloc memory for log variable (%d bytes) !", dwDumpedPESize );
		Error( szError);
		return 0xFFFF;
	}

	/* Truncating reserved block to zero */
	ZeroMemory(szDumpedPE, dwDumpedPESize);


	/* Preparing dump of DOS_STUB - first 16 bytes of.
	 * We will use here mine function HexChar which returns dot char or
	 * char sended as parameter if it's code is in allowed code area
	 */
	strcpy_s(szTmp2, sizeof(szTmp2)-1, "\r\n\t+----------------------------------------------------------------+\r\n");

	for(int i = 0; i < 64; i+=8 )
	{
		sprintf_s(szTmp, sizeof(szTmp)-1, 
					"\t| %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\t\t%c%c%c%c%c%c%c%c |\r\n", 
					g_DOS_STUB[i], g_DOS_STUB[i+1], g_DOS_STUB[i+2], g_DOS_STUB[i+3], 
					(HexChar(g_DOS_STUB[i+0]) ), (HexChar(g_DOS_STUB[i+1]) ),
					(HexChar(g_DOS_STUB[i+2]) ), (HexChar(g_DOS_STUB[i+3]) ),

					g_DOS_STUB[i+4], g_DOS_STUB[i+5], g_DOS_STUB[i+6], g_DOS_STUB[i+7], 		 
					(HexChar(g_DOS_STUB[i+4]) ), (HexChar(g_DOS_STUB[i+5]) ),
					(HexChar(g_DOS_STUB[i+6]) ), (HexChar(g_DOS_STUB[i+7]) )	 
		);
	}

	strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t+----------------------------------------------------------------+");

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

	time_t tTimeDateStamp = (time_t)g_image_file_header.TimeDateStamp;
	time_t tNowTDS;
	time( &tNowTDS);

	/* Preparing first skeleton of a log */
	sprintf_s( szDumpedPE,	dwDumpedPESize-1, 
							"\r\nPEInfo v0.4 by MGeeky, File research, dumped semi-raw PE Headers\r\n"
							"Current time/date stamp:\t( %s )\r\n"
							"----------------------------------------------------------------------------------------------\r\n"
							"\r\nFile:\t\"%s\"\r\nFile size:\t%lu bytes\r\n"
							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x00 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"DOS Header (IMAGE_DOS_HEADER) (sizeof: %dd)\r\n{\r\n\te_magic:\t\t%X;\t%s\r\n\t"
							"e_cblp:\t\t%X;\r\n\te_cp:\t\t%X;\r\n\te_crlc:\t\t%X;\r\n\te_cparhdr:\t%X;\r\n\t"
							"e_minalloc:\t%X;\r\n\te_maxalloc:\t%X;\r\n\te_ss:\t\t%X;\r\n\te_sp:\t\t%X;\r\n\te_"
							"csum:\t\t%X;\r\n\te_ip:\t\t%X;\r\n\te_cs:\t\t%X;\r\n\te_lfarlc:\t\t%X;\r\n\te_ovno:\t\t%X;\r\n\te_"
							"res:\t\t%X;\r\n\te_oemid:\t\t%X;\r\n\te_oeminfo:\t%X;\r\n\te_res2:\t\t%X;\r\n\te_lfanew:\t%X;\r\n};\r\n"

							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x01 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"DOS STUB - Dumped first 16 bytes (sizeof: %dd)\r\n{\r\n%s%s\r\n}\r\n"

							"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x02 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"NT Headers (IMAGE_NT_HEADERS32) (sizeof: %dd)"
							"\r\n{\r\n\tSignature:\t\t\t%X;\r\n"
							"\r\n\tFileHeader (IMAGE_FILE_HEADER) (sizeof: %dd)\r\n\t{\r\n"
							"\t\tMachine:\t\t\t%X;\r\n\t\tNumberOfSections:\t\t%X;\r\n\t\tTimeDateStamp:\t\t%X;\r\n"
							"\t\t\t\t\t(%s);\r\n\t\tPointerToSymbolTable:\t%X;\r\n\t\tNumberOfSymbols:\t\t%X;\r\n\t\t"
							"SizeOfOptionalHeader:\t%X;\r\n\t\tCharacteristics:\t\t%X;\r\n\t};\r\n"
							"\r\n\tOptionalHeader (IMAGE_OPTIONAL_HEADER32) (sizeof: %dd)\r\n\t{\r\n"
							"\t\tMagic:\t\t\t%X;\r\n\t\tMajorLinkerVersion:\t\t%X;\r\n\t\tMinorLinkerVersion:"
							"\t\t%X;\r\n\t\tSizeOfCode:\t\t%X;\r\n\t\tSizeOfInitializedData:\t%X;\r\n\t\tSizeOfUninitializedData"
							":\t%X;\r\n\t\tAddressOfEntryPoint:\t%X;\r\n\t\tBaseOfCode:\t\t%X;\r\n\t\tBaseOfData"
							":\t\t%X;\r\n\t\tImageBase:\t\t%X;\r\n\t\tSectionAlignment:\t\t%X;\r\n\t\tFileAlignment"
							":\t\t%X;\r\n\t\tMajorOperatingSystemVersion:\t%X;\r\n\t\tMinorOperatingSystemVersion"
							":\t%X;\r\n\t\tMajorImageVersion:\t%X;\r\n\t\tMinorImageVersion:\t\t%X;\r\n\t\tMajorSubsystemVersion"
							":\t%X;\r\n\t\tMinorSubsystemVersion:\t%X;\r\n\t\tWin32VersionValue:\t\t%X;\r\n\t\tSizeOfImage"
							":\t\t%X;\r\n\t\tSizeOfHeaders:\t\t%X;\r\n\t\tCheckSum:\t\t%X;\r\n\t\tSubsystem:\t\t%X;\r\n\t\t"
							"DllCharacteristics:\t\t%X;\r\n\t\tSizeOfStackReserve:\t%X;\r\n\t\tSizeOfStackCommit"
							":\t%X;\r\n\t\tSizeOfHeapReserve:\t%X;\r\n\t\tSizeOfHeapCommit:\t\t%X;\r\n\t\tLoaderFlags"
							":\t\t%X;\r\n\t\tNumberOfRvaAndSizes:\t%X;\r\n\t}; // OptionalHeader\r\n\r\n}; // NT Headers",

							ctime( &tNowTDS ), g_szFilePath, (dwSizeLow+dwSizeHigh), sizeof(IMAGE_DOS_HEADER), 
							g_image_dos_header.e_magic, ((g_image_dos_header.e_magic == 0x5A4D)? "(MZ)" : "(??)" ),
							g_image_dos_header.e_cblp, g_image_dos_header.e_cp, g_image_dos_header.e_crlc,  
							g_image_dos_header.e_cparhdr, g_image_dos_header.e_minalloc, g_image_dos_header.e_maxalloc, 
							g_image_dos_header.e_ss, g_image_dos_header.e_sp, g_image_dos_header.e_csum, 
							g_image_dos_header.e_ip, g_image_dos_header.e_cs, g_image_dos_header.e_lfarlc, 
							g_image_dos_header.e_ovno, g_image_dos_header.e_res, g_image_dos_header.e_oemid, 
							g_image_dos_header.e_oeminfo, g_image_dos_header.e_res2, g_image_dos_header.e_lfanew,
							sizeof(g_DOS_STUB), szTmp2, szTmp, sizeof(IMAGE_NT_HEADERS32), g_ulNT_Signature, 
							sizeof(IMAGE_FILE_HEADER), g_image_file_header.Machine, g_image_file_header.NumberOfSections,
							g_image_file_header.TimeDateStamp, ctime(&tTimeDateStamp), 
							g_image_file_header.PointerToSymbolTable,
							g_image_file_header.NumberOfSymbols, g_image_file_header.SizeOfOptionalHeader,
							g_image_file_header.Characteristics, sizeof(IMAGE_OPTIONAL_HEADER32), 
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
							g_image_optional_header.CheckSum, g_image_optional_header.Subsystem, 
							g_image_optional_header.DllCharacteristics, g_image_optional_header.SizeOfStackReserve,
							g_image_optional_header.SizeOfStackCommit, g_image_optional_header.SizeOfHeapReserve, 
							g_image_optional_header.SizeOfHeapCommit, g_image_optional_header.LoaderFlags, 
							g_image_optional_header.NumberOfRvaAndSizes
	);

	/* Addinational info for sections loop */
	sprintf_s(szTmp, sizeof(szTmp)-1, "\t#\tSize\tVA\r\n");

	/* A tables to pointers of chars. 
	 * This names is next names of DataDirectory indexes 
	 */
	char *szOptionalHeadersNames[ ] = 
	{
		"Export Symbols", "Import Symbols", "Resources", "Exception", 
		"Security", "Base Relocation", "Debug", "Copyright string", "GlobalPtr",
		"Thread Local Storage [TLS]", "Load Configuration", "Bound Import",
		"Import Address Table", "Delay Import", "COM Descriptor", "Reserved"
	};

	strcat_s(szDumpedPE, dwDumpedPESize-1, "\r\n\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-=-"
						" [ 0x03 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
						"IMAGE_OPTIONAL_HEADER32->DataDirectory dump:\r\n{\r\n");

	/* A ssections information loop.
	 * This loop prepares infos about sections from 
	 * IMAGE_DATA_DIRECTORY structure values.
	 */
	strcat_s(szDumpedPE, dwDumpedPESize-1, "\t#\tVA\tSize\r\n\t--------------------------------------\r\n");

	for(unsigned i = 0; i < 16; i++)
	{
		sprintf_s(szTmp, "\t%d.)\t%X\t%X\t\t// %s\r\n", i,
				g_image_optional_header.DataDirectory[i].VirtualAddress,
				g_image_optional_header.DataDirectory[i].Size, 
				szOptionalHeadersNames[i]);
		strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);
	}

	strcat_s(szDumpedPE, dwDumpedPESize-1, "\r\n}; // DataDirectory\r\n\r\n");
	
	ZeroMemory(szTmp, dwTmpSize);
	
	/* Appending extra, cosmetical chars */
	sprintf_s(szTmp, sizeof(szTmp)-1, "%dd)\r\n{\r\n", sizeof(IMAGE_SECTION_HEADER) );
	strcat_s(szDumpedPE, dwDumpedPESize-1,	"\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x04 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
						"All Sections Info (gathered from IMAGE_SECTION_HEADERs ) (sizeof: ");
	strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);

	/* Important loop.
	 * In this loop we will describe every section,
	 * by using informations saved in each IMAGE_SECTION_HEADER
	 * structure. 
	 */
	char szName[32] = "";

	for(int i = 0; i < g_image_file_header.NumberOfSections; i++)
	{
		pImage_section_header = &g_image_section_header[i];

		strncpy(szName, (const char*)pImage_section_header->Name, 7);
		szName[strlen(szName)+1] = '\0';

		ZeroMemory(szTmp, dwTmpSize);
		sprintf_s(szTmp, sizeof(szTmp)-1, "\t// ::::::::::::::::::\r\n\tIMAGE_SECTION_HEADER[%d]\r\n\t{"
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
		strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);
	}


	/* Here we appending some chars */
	strcat_s(szDumpedPE, dwDumpedPESize-1, "\r\n}; // Sections Info\r\n\r\n" );
	ZeroMemory(szTmp, dwTmpSize);

	/* Recognizing Machine.
	 * Here we will read value from IMAGE_FILE_HEADER->Machine,
	 * and make proper message.
	 */
	switch( g_image_file_header.Machine)
	{
	case IMAGE_FILE_MACHINE_ALPHA:
		strcpy_s(szTmp, sizeof(szTmp)-1, "ALPHA\t- DEC Alpha architecture");
		break;
	case IMAGE_FILE_MACHINE_I386:
		strcpy_s(szTmp, sizeof(szTmp)-1, "I386\t- 80386 arch. application");
		break;
	case IMAGE_FILE_MACHINE_UNKNOWN:
		strcpy_s(szTmp, sizeof(szTmp)-1, "UNKNOWN\t- Unknown machine");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		strcpy_s(szTmp, sizeof(szTmp)-1, "IA64\t- Intel (64bit) arch");
		break;
	case IMAGE_FILE_MACHINE_AXP64:
		strcpy_s(szTmp, sizeof(szTmp)-1, "AXP64\t- Alpha (64bit) / AXP64 arch");
		break;
	case IMAGE_FILE_MACHINE_AM33:
		strcpy_s(szTmp, sizeof(szTmp)-1, "AM33\t- AM33 arch");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		strcpy_s(szTmp, sizeof(szTmp)-1, "AMD64\t- AMD 64bit architecture");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		strcpy_s(szTmp, sizeof(szTmp)-1, "POWERPC\t- PowerPC architecture");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		strcpy_s(szTmp, sizeof(szTmp)-1, "MIPSFPU\t- MIPS FPU arch");
		break;
	default:
		strcpy_s(szTmp, sizeof(szTmp)-1, "Other, not recognized architecture");
		break;
	}


	/* Adding some extra chars (for cosmetical purposes ) */
	strcpy_s(szTmp2, sizeof(szTmp2)-1, szTmp);
	ZeroMemory(szTmp, dwTmpSize );
	sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n\r\n-=-=-=-=-=-=-=-=-=-=-=-=-=- [ 0x05 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
					"Additional Informations about a file, gathered from some PE Headers values.\r\n{\r\n\t"
			"1. CPU Platfrom identified by 'Machine':\r\n\t\t%s;", szTmp2);
	strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);

	/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */

	ZeroMemory(szTmp, dwTmpSize);

	/* This is next step in describing file.
	 * Here we will try to stretch out a flag, and
	 * if this flag will be present in Characteristics
	 * value, then we prepare proper message.
	 */
	if( g_image_file_header.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- There are no informations about \"relocations\";");
	if( g_image_file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- This is an Executable File (not .OBJ or .LIB);");
	if( g_image_file_header.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- There are no line numbers in file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Local symbols are not in file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Application can address more than 2 Gigabytes;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_32BIT_MACHINE) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- For 32 bit machines;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Informations about symbols are in *.dbg file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- copy and run from SWAP;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- when file is in the net, copy and run from SWAP;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_SYSTEM) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- System file;");
	if( g_image_file_header.Characteristics & IMAGE_FILE_DLL) 
		strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Dynamic Link Library file;");

	if( strlen(szTmp ) == 0) strcpy_s(szTmp, sizeof(szTmp)-1, "There is no valid flags set in Characteristics!");

	strcpy_s(szTmp2, sizeof(szTmp2)-1, szTmp);
	ZeroMemory(szTmp, dwTmpSize );
	sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n\r\n\t2. Files characteristics:\r\n\t{%s\r\n", szTmp2);
	strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);

	/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
	
	ZeroMemory(szTmp, dwTmpSize);

	/* Here we read information about application subsystem, 
	 * and then prepares a message 
	 */
	switch(g_image_optional_header.Subsystem)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Unknown Subsystem;");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- No subsystem required (device drivers and native system processes);");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Windows graphical user interface (GUI) subsystem;");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Windows character-mode user interface (CUI) subsystem;");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- OS/2 CUI subsystem;");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Windows CE system;");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Extensible Firmware Interface (EFI) application;");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- EFI driver with boot services;");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- EFI driver with run-time services;");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- EFI Rom Image;");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- XBox subsystem file;");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		strcpy_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Boot application (BootLoader);");
		break;
	}

	strcpy_s(szTmp2, sizeof(szTmp2)-1, szTmp);
	ZeroMemory(szTmp, dwTmpSize );
	sprintf_s(szTmp, sizeof(szTmp)-1, "\t}; // File characteristics\r\n\r\n\t3."
									" Recognized Subsystem of this file:%s\r\n", szTmp2);
	strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);

	/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */

	ZeroMemory(szTmp, dwTmpSize);
	
	/* Now, stretching out flags, 
	 * which will tell about file characteristics. 
	 */
	if(g_image_file_header.Characteristics & IMAGE_FILE_DLL)
	{
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- The DLL can be relocated at load time;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Code integrity checks are forced;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- The image is compatible with data execution prevention (DEP)");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- The image is isolation aware, but should not be isolated;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- The image is isolation aware, but should not be isolated;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- Do not bind the image;");
		if( g_image_optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) 
			strcat_s(szTmp, sizeof(szTmp)-1, "\r\n\t\t- The image is terminal server aware;");
		
		if( strlen(szTmp) == 0) strcpy_s(szTmp, sizeof(szTmp)-1, 
											"\t\t[!] There are'nt valid DLL Characteristics flags value !");
		
		sprintf_s(szTmp2, "\r\n\t4. DLL File characteristics:\r\n\t{\r\n%s\r\n\t}; // DLL Characteristics\r\n", szTmp);
		strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp2);

	}else
	{
		strcat_s(szDumpedPE, dwDumpedPESize-1, "\r\n\t4. DLL File characteristics NOT AVAILABLE\r\n");
	}

	ZeroMemory(szTmp, dwTmpSize );
	
	// Reading Import Table if available.
	if( g_image_optional_header.DataDirectory[1].Size > 0x10 )
	{
		strcat_s(szDumpedPE, dwDumpedPESize-1, 
							"\r\n}; // Additional Infos\r\n\r\n\r\n-=-=-=-=-=-"
							"=-=-=-=-=-=-=-=- [ 0x06 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"PE Import data view (IAT + IMAGE_IMPORT_DESCRIPTORs)\r\n{\r\n");

		List_IAT(szDumpedPE, dwDumpedPESize - 1);

		strcat_s(szDumpedPE, dwDumpedPESize-1, "\r\n\r\n}; // PE Import Table\r\n\r\n");
	}else
	{
		MessageBoxA(NULL,	"WARNING !\r\nThere is no Import table available in file !"
							"\r\nIt's may meaning the file is broken/encrypted(?)/or "
							"this PE file just have no valid import table (which means "
							"incorrect work of this file).\r\n\r\nPlease take some "
							"distance to log created by PEInfo because it's may be invalid.", 
							"Warning!", MB_ICONWARNING|MB_APPLMODAL);
	}

	// Reading Export Table if available.
	if( g_image_optional_header.DataDirectory[0].Size > 0x10 )
	{
		strcat_s(szDumpedPE, dwDumpedPESize-1, 
							"\r\n\r\n-=-=-=-=-=-"
							"=-=-=-=-=-=-=-=- [ 0x07 ] -=-=-=-=-=-=-=-=-=-=-=-=-=-\r\n"
							"PE Export data view (EAT + IMAGE_EXPORT_DIRECTORY)\r\n{\r\n");

		List_EAT(szDumpedPE, dwDumpedPESize - 1);

		strcat_s(szDumpedPE, dwDumpedPESize-1, "\r\n\r\n}; // PE Export Table\r\n\r\n");
	}

	bool bIsExportAvailable = (g_image_optional_header.DataDirectory[0].Size > 0x10);


	/* Adding some extra chars (for cosmetical purposes ) */
	strcat_s(szDumpedPE,	dwDumpedPESize-1, "\r\n\r\n\r\n------------------------------------------------"
						"----------------------------------------------\r\n");


	g_dwPreparingLogTime = GetTickCount() - dwStart;

#ifdef _DEBUG
	if( bIsExportAvailable)
	{
		sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n[?] Informations about PE Headers collected in\t%dms;\r\n"
					"[?] Import Table read in\t\t\t%dms;\r\n[?] Export Table read in\t\t\t%dms;\r\n[?] "
					"Log prepared in\t\t\t\t%dms;\r\n\r\n[?] Log length:\t\t\t\t%lu bytes;", 
					g_dwCollectingTime, g_dwReadingIATTime, g_dwReadingEATTime, 
					g_dwPreparingLogTime+5, strlen(szDumpedPE));
	}else
	{
		sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n[?] Informations about PE Headers collected in\t\t\t%dms;\r\n"
					"[?] Import Table read in\t\t\t%dms;\r\n[?] Log prepared in\t\t\t\t%dms;"
					"\r\n\r\n[?] Log length:\t\t\t\t%lu bytes;", 
					g_dwCollectingTime, g_dwReadingIATTime, g_dwPreparingLogTime+5, strlen(szDumpedPE));
	}
#endif

	sprintf_s(szTmp, sizeof(szTmp)-1, "\r\n[?] Log length:\t\t\t\t%lu bytes;", strlen(szDumpedPE));

	strcat_s(szDumpedPE, dwDumpedPESize-1, szTmp);

	// Setting prepared log to the read-only editbox window. 
	SendMessageA(hwnd, EM_LIMITTEXT, (WPARAM)strlen(szDumpedPE) + 3, 0);
	SetWindowTextA( hwnd, szDumpedPE);

	ZeroMemory(szDumpedPE, dwDumpedPESize);

	/* Freeing resources */
	free((void*)szDumpedPE);
	szDumpedPE = NULL;
	
	/* Ending thread */
	_endthreadex(0);
	return 0;
}


/* ///////////////////////////////////////////////////////////////////////////////////////// */
// This functions examine sended as parameter char code, and returns it or dot code

char HexChar(int c)
{
	if( c >= 0x21 && c <= 0x7D)return (char)c;
	else return '.';
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
