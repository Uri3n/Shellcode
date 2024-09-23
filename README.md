# Shellcode
Shellcode is position independent code that can be ran from any location
in memory (as long as the pages are executable), as opposed to your 
typical executable which needs to undergo several steps taken by the 
operating system to be ran. 

Shellcode is typically used and abused by exploit and malware developers 
for various malicious purposes. This is because:
- Shellcode is flexible and applicable to many use cases.
- It can easily be hidden or obfuscated.
- It has minimal footprint on the system it runs on.
  Shellcode often never touches disk, because it can be kept entirely in-memory.

# Windows vs Linux Shellcode
All of the shellcode featured here is for Windows. Linux shellcode is far less difficult to create, primarily because you are able to perform syscalls directly, from any location. On Windows this is also technically possible, as there's no restriction on where a syscall instruction can be executed from per se. The issue is that the SSNs (Syscall Service Numbers) of each system call are randomized per Windows version, meaning you're better off dynamically resolving the addresses of Win32 functions instead. Because Linux shellcode is tremendously simple to create by comparison, I opted to not bother including any, but there are plenty of resources on that topic online if you're interested.

# What's here?
- A few shellcode samples to learn how it's written (some assembly, some C++).
- A script to help with creation of the shellcode.
- The payloads in raw binary format.
- The payloads in a C-style array format.
- **calc**: written in pure assembly, specifically MASM (Microsoft's "Macro Assembler"). Simply opens the calculator app. Similar to the one found in the MSFVenom toolkit.
- **msgbox**: written in C++. Pops a message box.
- **reverse_shell**: A basic reverse shell payload that redirects the input and output of a command prompt process (spawned via Win32 CreateProcess) into a TCP socket. For testing purposes this payload will reach out to **localhost 4444**. You can listen on this port with say, netcat, if you want to mess around with it (i.e. something like `nc -l 127.0.0.1 4444` will work). If you want to have it connect to a different socket you can modify the stack string at the beginning of the rshell_impl() function as well as the host port.

# How do I build these payloads?
I'd highly recommend messing around with the source code and building it yourself. Unfortunately, shellcode is rather tricky when it comes to the build process. You cannot simply hit build and expect everything to work. Take note of the fact that there is a Python script called _scn_dump_ in the scripts folder that will extract the .text section from a given executable and dump it into a file of your choosing. You'll need this.

### Building MASM (Assembly) Shellcode
This pertains to the MASM shellcode found here (like calc.asm). to turn it into shellcode, you'll first need to open up the **Visual Studio x64 Native Tools Command Prompt** that comes with every install of Visual Studio. Next, do the following:
- `ml64.exe /c calc.asm` this will run Microsoft's MASM assembler on the file and produce a COFF object file.
- `link.exe /entry:calc /subsystem:console calc.obj` invoke Microsoft's native linker on the object file to create a PE.
- `scn_dump.py calc.exe calc.bin` use the Python script included in this repo to dump the .text section of the PE into a .bin file. 
- Load and execute the .bin using whatever method you want. It'll work as long as the page has execute perms.

### Building C++ Shellcode
This pertains to the shellcode here written in C++ (i.e. reverse_shell.cpp and msgbox.cpp). They make use of **inline assembly** for stack alignment purposes, which means we can't use MSVC to compile them (MSVC does not natively support inline assembly for 64 bit programs). To compile, you'll need 64 bit G++ (the C++ version of GCC basically) installed on your Windows machine. Run these commands:
- `x86_64-w64-mingw32-g++ <FILE> -Os -nostdlib -s -masm=intel -fPIC -o shellcode.exe` replace \<FILE\> with the name of the .cpp file.
- `scn_dump.py shellcode.exe shellcode.bin` This will dump the .text section, allowing it to be loaded and executed.


