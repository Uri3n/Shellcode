.code

public calc
calc proc
	; init/prologue:
	; - save all non-volatile registers
	; - zero out some registers so we can use them

	push r15
	push r14
	push r13
	push r12
	push rbp
	push rdi
	push rsi
	push rbx

	xor rax, rax 
	xor rbx, rbx 
	xor rdi, rdi
	xor r10, r10
	xor r11, r11
	xor r12, r12

	;iterate through PEB
	mov rbx, gs:[rax + 60h]	; rbx = PEB addr
	mov rbx, [rbx + 18h]	; rbx = LDR
	mov rbx, [rbx + 20h]	; rbx = NTDLL entry
	mov rbx, [rbx]		    ; rbx = KernelBase Entry
	mov rbx, [rbx]		    ; rbx = Kernel32 Entry
	mov rbx, [rbx + 20h]	; rbx = &K32 Base

	;Get export table
	mov r8, rbx		        ; save base address for RVAs
	mov ebx, [rbx + 3Ch]	; ebx = e_lfanew
	add rbx, r8		        ; rbx = PIMAGE_NT_HEADERS
	
	xor rcx, rcx
	mov cx, 88h
	mov edx, [rbx + rcx]	; edx = NT_HEADERS->OptionalHeader.DataDirectory[0].VirtualAddress
	add rdx, r8		        ; rdx = PIMAGE_EXPORT_DIRECTORY

	mov r10d, [rdx + 1ch]   ; R10 = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	add r10, r8 

	mov r11d, [rdx + 20h]   ; R11 = IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add r11, r8

	mov r12d, [rdx + 24h]   ; R12 = IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	add r12, r8

	jmp short winexec

	get_func_addr:
		pop rbx					        ; rbx = WinExec label return
		pop rcx							
		xor rax, rax				    ; rax will be our counter
		mov rdx, rsp				    ; rdx = string pointer
		push rcx

		iterate_exports:
			mov rcx, [rsp]			    ; rcx = string length
			xor rdi, rdi
			mov edi, [r11 + rax * 4]	; RVA = AddressOfNames + Counter + sizeof(DWORD)
			add rdi, r8			        ; rdi = address of string
			
			mov rsi, rdx
			repe cmpsb			        ; String comparison, finish if equal
			je final_resolve_addr
			
			inc rax
			jmp short iterate_exports


	final_resolve_addr:
		pop rcx					        ; rcx = string length
		mov ax, [r12 + rax * 2]			; OrdinalRVA = AddressOfNameOrdinals + counter + sizeof(WORD)
		mov eax, [r10 + rax * 4]		; FunctionRVA = AddressOfFunctions + ordinal number + sizeof(DWORD)
		add rax, r8				        ; rax = FunctionRva + BaseAddress
		
		push rbx				        ; rsp = return address
		ret					            ; restore control flow back to WinExec label


	winexec:
		xor rcx, rcx
		add cl, 7h				        ; length of "WinExec"
		mov rax, 00636578456E6957h		; "00WinExec"
		
		push rax				        ; push string
		push rcx				        ; push string length
		
		call get_func_addr
		mov r14, rax				    ; r14 = WinExec address

		xor rcx, rcx
		xor rdx, rdx
		xor rax, rax

		push rax				        ; null terminate the stack string
		mov rax, 6578652E636C6163h		; "calc.exe"

		push rax
		mov rcx, rsp				    ; rcx = "calc.exe",0
		mov rdx, 1h				        ; rdx = 0x1 (SW_SHOWNORMAL)
		
		mov rsi, rsp                    ; save rsp
		and rsp, 0FFFFFFFFFFFFFFF0h     ; align rsp to a 16-byte boundary
		sub rsp, 60h                    ; make some room on the stack
		call r14                        ; WinExec("calc.exe", SW_SHOWNORMAL)
		mov rsp, rsi                    ; restore the stack pointer to the value before the call

		; cleanup:
		; - move rsp past the two 8 byte values we pushed onto the stack before the call.
		; - restore non volatile registers via pop operations.
		; - move rsp to the beginning of the return address (subtract another 8 bytes).
		; - return.

		add rsp, 10h                    
		pop rbx
		pop rsi
		pop rdi
		pop rbp
		pop r12
		pop r13
		pop r14
		pop r15
                    
		add rsp, 8h
		mov rax, 0h

		ret
calc endp

end
