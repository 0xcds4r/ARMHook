#include "main.h"
#include "ARMHook.h"

#include <ucontext.h>
#include <pthread.h>
#include <dlfcn.h>

uintptr_t g_libPtr = 0;

// ---------------------------------------------------------------------------------------------------------

int Travis_hook(int value)
{
	value += 10;

	/* --------- EXAMPLES --------- */
	int retn_result = (( int (*)(int))(g_libPtr+0x244F2C+1))(value); // call func by addr 
	// (( "return type" (*)( "value type" ))( "address" ))( "value" );

	// ... YOuR C0de h3re ...

	return retn_result;
}

void (*GameLoop)(int value); // orig
void GameLoop_hook(int value)
{
	if(value > 0xFF)
		return GameLoop(value); // call original (if value > 255)

	// call original
	GameLoop(value);

	// .... yoUR c0d3 here ....

	/* --------- EXAMPLES --------- */
	// Make NOP
	ARMHook::makeNOP(g_libPtr+0x2454E5, value);
}

// ---------------------------------------------------------------------------------------------------------

void Main()
{
	/* --------- EXAMPLES --------- */

	// unprotect
	ARMHook::unprotect(g_libPtr+0x14543A);

	// write & read memory
	ARMHook::writeMem(g_libPtr+0x12143A, (uintptr_t)"\xF5\xF1\x05", 2);
	uintptr_t value = *(uintptr_t*)(g_libPtr+0x14543A);

	if(value > 30)
	{
		*(uintptr_t*)(g_libPtr+0x14543A) -= 30;
	}

	// hooks
	ARMHook::installHook(g_libPtr+0x13E3DC, (uintptr_t)GameLoop_hook, (uintptr_t*)&GameLoop);

	// method hooks
	ARMHook::installMethodHook(g_libPtr+0x1FDC10, (uintptr_t)Travis_hook);	

	// rets
	ARMHook::makeRet(g_libPtr+0x5AAC15); // return 0;
}

void *InitialiseThread(void *p)
{
	Main();
	pthread_exit(0);
}          

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
	g_libPtr = ARMHook::getLibraryAddress("libName.so");

	if(g_libPtr)
	{
		srand(time(0));

		uintptr_t memlib_start = (g_libPtr + 0x1234FA);
		uintptr_t size = 0x400; // memlib_end = memlib_start + size
		
		ARMHook::InitialiseTrampolines(memlib_start, size);

		pthread_t thread;
		pthread_create(&thread, 0, InitialiseThread, 0);
	}

	return JNI_VERSION_1_6;
}

uint32_t GetTickCount()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return (tv.tv_sec*1000+tv.tv_usec/1000);
}