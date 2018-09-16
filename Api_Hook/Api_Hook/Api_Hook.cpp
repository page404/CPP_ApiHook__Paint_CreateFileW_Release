// Api_Hook.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "Api_Hook.h"

#define MAX_LOADSTRING 100

// 全局变量: 
HINSTANCE hInst;								// 当前实例
TCHAR szTitle[MAX_LOADSTRING];					// 标题栏文本
TCHAR szWindowClass[MAX_LOADSTRING];			// 主窗口类名

// 此代码模块中包含的函数的前向声明: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

char *g_szHello = "Hello world!";
char *g_szTitle = "Page404";

char *g_szClassName = "MSPaintApp";

char *g_szKernel32 = "Kernel32";
char *g_szUser32 = "User32";

char *g_szSleep = "Sleep";
char *g_szMsgBox = "MessageBoxW";

char *g_hInst;

typedef struct tagTrueAddr
{

	BYTE g_JmpCode;
	long g_JmpOffset;

}TrueAddr, *PTrueAddr;

__declspec(naked) void __stdcall InjectCode(FARPROC lpMsgBox){

	__asm{

		//保存各寄存器环境变量
		pushad

		//----  动态重定位(运行时(call NEXT)的地址 减去 编译时(offset)的地址), 即相对偏移
		//INJECTCODE_BEGIN 到 INJECTCODE_END 这段代码是注入到扫雷的内存当中去的, 所以偏移地址跟我们自己的hello.exe肯定不一样, 所以要用动态重定位的方式来计算偏移量
		//并在下面调用系统的 LoadLibrary->GetProcAddress 得到 MessageBoxA 及 Sleep 等系统 api 的固定地址
		//最后, 将 相对偏移地址 + 固定地址, 即是我们程序运行时, 调用的系统api地址.
		//这样处理, 不管注入任何的exe中, 都是计算要注入exe运行时所调用的系统api地址.
		call NEXT
		NEXT :
		pop ebx
		sub ebx, offset NEXT

		push MB_OK
		push NULL
		mov eax, [esp + 2ch]  //esp + 2ch: 保存图片的全路径,因为hook的是CreateFileW这个系统api,所以,路径就在该函数附近
		push eax
		push NULL
		call[InjectCode - 4 + ebx]  //InjectCode - 4 :为我们写入内存时,MessageBox在系统User32.dll中的位置

		//还原各寄存器环境变量
		popad
		//被 hook 替换掉的那一行代码,现在要写回去.
		mov   eax, 10362A5h

		//------101d1a2h hook目标内存行的下一行地址.
        //push + ret 相当于 jmp
        //如果直接用 jmp ,那么还要计算代码的相对偏移地址.
        //如果想用 jmp ,那么,得先把跳转地址存先存放到寄存器,再调用,如: mov ecx,101d1a2h  jmp ecx ,但是,必须确认 ecx 在后面是否有用到,如果用到了,值会被覆盖.
		push  101d1a2h
		ret
	}

}

void Inject(){

	FARPROC g_lpMsgBox;
	FARPROC g_lpSleep;

	//查找到的窗口句柄
	HWND hWnd;
	//进程的标识符
	DWORD dwPID;
	//打开进程的句柄
	HANDLE hProcess;
	//所分配内存的基地址
	LPVOID lpMem;
	HANDLE hThread;
	DWORD nInjectCodeSize;
	DWORD dwOld;
	BOOL bRet;
	HMODULE hMoudle;

	try{

		//调用 FindWindow api函数
		hWnd = FindWindow(g_szClassName, NULL);
		if (hWnd == NULL){
			throw;
		}
		//得到目标进程的ID
		GetWindowThreadProcessId(hWnd, &dwPID);
		//调用 OpenProcess api函数,建立两个进程之间的联系
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if (hProcess == NULL){
			throw;
		}

		//计算要注入到目标内存中的代码的长度
		nInjectCodeSize = ((long)Inject - (long)InjectCode);

		//调用 VirtualAllocEx api函数, 开辟内存空间
	    //这里的 @hProcess 为查找到的窗口(即画图)的进程句柄, 所以是在画图里面分配的内存空间
		lpMem = VirtualAllocEx(hProcess, NULL, nInjectCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (lpMem == NULL){
			throw;
		}

		hMoudle = LoadLibrary(g_szUser32);
		if (hMoudle == NULL){
			throw;
		}
		//得到 User32 中的 MessageBox 函数的 地址
		g_lpMsgBox = GetProcAddress(hMoudle, g_szMsgBox);
		if (g_lpMsgBox == NULL){
			throw;
		}

		//调用 WriteProcessMemory api函数,写入代码到画图的内存
		bRet = WriteProcessMemory(hProcess, (LPVOID)((int)lpMem + 4), (LPCVOID)InjectCode, nInjectCodeSize+4, NULL);
		if (bRet == FALSE){
			throw;
		}

		//将 MessageBox弹出框 写入内存
		bRet = WriteProcessMemory(hProcess, lpMem, (LPCVOID)&g_lpMsgBox, sizeof(FARPROC), NULL);
		if (bRet == FALSE){
			throw;
		}

		//---我们自己拼凑的5个字节的指令
		TrueAddr trueAddr;
		trueAddr.g_JmpCode = 0xe9; //长 jmp 的机器码是 e9,即占 5个字节 , 短 jmp 的机器码是 EB,即占 2个字节
		long writeFileW_NextLine = 0x101d19d + 0x5; //101d19dh 地址为 writeFileW 的函数指针调用入口处地址,长 jmp 的机器码是 e9,即占 5个字节.
		long runCodePosition = (long)lpMem + 0x4;
		//g_JmpOffset 为替换后的 jmp 后面的 4个字节地址值 (jmp 后面的地址是相对偏移地址)
		trueAddr.g_JmpOffset = runCodePosition - writeFileW_NextLine;

		//101d19dh 地址为 writeFileW 的函数指针调用入口处地址.
		LPVOID nAddr = (LPVOID)0x101d19d;

		//写入内存,替换 0x101d19d 内存处的 5 个指令
		bRet = WriteProcessMemory(hProcess, nAddr , (LPCVOID)(&trueAddr.g_JmpCode), 5, NULL);
		if (bRet == FALSE){
			throw;
		}

	}
	catch (...){

		if (hThread == NULL){
			CloseHandle(hThread);
			hThread = NULL;
		}

		//if (lpMem == NULL){
		//	VirtualFreeEx(hProcess, lpMem, nInjectCodeSize, MEM_RELEASE);
		//	lpMem = NULL;
		//}

		if (hProcess == NULL){
			CloseHandle(hProcess);
			hProcess = NULL;
		}

	}

	return;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;
	HFONT hFont;

	switch (message)
	{
	case WM_LBUTTONDOWN:
		Inject();

	case WM_COMMAND:
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// 分析菜单选择: 
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO:  在此添加任意绘图代码...

		LOGFONT logfont; //改变输出字体
		ZeroMemory(&logfont, sizeof(LOGFONT));
		logfont.lfCharSet = GB2312_CHARSET;
		logfont.lfHeight = -16; //设置字体的大小
		hFont = CreateFontIndirect(&logfont);
		::SetTextColor(hdc, RGB(255, 0, 0));
		::SetBkColor(hdc, RGB(200, 200, 0));
		::SetBkMode(hdc, TRANSPARENT);
		SelectObject(hdc, hFont);

		RECT  rt;
		GetClientRect(hWnd, &rt);
		DrawText(hdc, TEXT("先打开画图软件,再在我们自己软件的界面上单击鼠标左键,最后将所画的图片另存为,会弹出所保存图片的全路径."), -1, &rt, DT_CENTER);

		DeleteObject(hFont);

		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO:  在此放置代码。
	MSG msg;
	HACCEL hAccelTable;

	// 初始化全局字符串
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_API_HOOK, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// 执行应用程序初始化: 
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_API_HOOK));

	// 主消息循环: 
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int) msg.wParam;
}



//
//  函数:  MyRegisterClass()
//
//  目的:  注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_API_HOOK));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_API_HOOK);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//
//   函数:  InitInstance(HINSTANCE, int)
//
//   目的:  保存实例句柄并创建主窗口
//
//   注释: 
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // 将实例句柄存储在全局变量中

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  函数:  WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目的:    处理主窗口的消息。
//
//  WM_COMMAND	- 处理应用程序菜单
//  WM_PAINT	- 绘制主窗口
//  WM_DESTROY	- 发送退出消息并返回
//
//


// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
