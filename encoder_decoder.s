; The encoder encodes each byte of a given address space using one of nine different XOR keys.
; The key is changed after each XOR operation. The encoder will cycle through each key and start over
; once it uses the last key.


global _start
section .text
_start:

PUSHAD                                                                  ; saves registers
PUSHFD                                                                  ; saves flags
MOV ESI, 0x00401000                                                     ; start of encode/decode
PUSH ESI                                                                ; push address to stack

GetKey:
CALL SetKey                                                             ; call SetKey label
Key: DB 0xA1, 0xFB, 0x86, 0x97, 0x11, 0x3C, 0x55, 0xD6, 0xE4
KeyEnd: EQU $-Key                                                       ; Set the size of the decipher key to KeyEnd label

SetKey:
POP EDI                                                                 ; moves start of xor key to EDI
NOP
XOR EDX, EDX                                                            ; EDX = 0

Decipher:
MOV AL,[ESI]                                                            ; moves first byte from .text section to AL
NOP
NOP
MOV BL,[EDI]                                                            ; moves first xor key to BL
XOR AL,BL                                                               ; xor AL with xor key
MOV [ESI],AL                                                            ; moves result of xor to [ESI]
INC ESI                                                                 ; increments ESI by 1
NOP
NOP
INC EDI                                                                 ; increments EDI by 1 - xor key counter
NOP
INC EDX                                                                 ; increments EDX by 1
NOP
CMP ESI, 0x004018DF                                                     ; end of encode/decode address
NOP
JE Fin                                                                  ; jump if true
CMP EDX, KeyEnd                                                         ; check if we reached the end of the keys
NOP
JE GetKey                                                               ; jump if true
JMP Decipher                                                            ; keep encoding/decoding

Fin:
POPFD                                                                   ; restores flags (not really, should add pop address
                                                                        ; before this command)
POPAD                                                                   ; restores registers (not really, same as above)

RET                                                                     ; not used - change to jmp address in debugger
