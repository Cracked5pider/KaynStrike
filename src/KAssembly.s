EXTERN KaynLoader

GLOBAL Start

GLOBAL KaynCaller
GLOBAL KRip

SECTION .text
	Start:
		push	rsi
		mov	    rsi, rsp
		and	    rsp, 0FFFFFFFFFFFFFFF0h

		sub	    rsp, 020h
		call	KaynLoader

		mov		rsp, rsi
		pop		rsi
	ret

SECTION .text
    KaynCaller:
           call caller
       caller:
           pop rcx
       loop:
           xor rbx, rbx
           mov ebx, 0x5A4D
           inc rcx
           cmp bx,  word ds:[ rcx ]
           jne loop
           xor rax, rax
           mov ax,  [ rcx + 0x3C ]
           add rax, rcx
           xor rbx, rbx
           add bx,  0x4550
           cmp bx,  word ds:[ rax ]
           jne loop
           mov rax, rcx
       ret

   KRip:
       call    ptr
   ptr:
       pop     rax
       sub     rax, 5
       ret