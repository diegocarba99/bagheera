BITS 64


global _start


section .text


_start:

	; Save register state, RBX can be safely used
	push rax
	push rcx
	push rdx
	push rbx
	push rsi
	push rdi
	push rsp
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15


	
	jmp	parasite
	message:	db	"[!] fear Bagheera's mighty claw  [!]", 0xa

parasite:
	; Print our message
	xor	rax, rax					; Zero out RAX
	add	rax, 0x1					; Syscall number of write() - 0x1
	mov rdi, rax					; File descriptor - 0x1 (STDOUT)
	lea rsi, [rel message]			; Addresses the label relative to RIP (Instruction Pointer), i.e. 
									; dynamically identifying the address of the 'message' label.
	xor rdx, rdx
	mov dl, 0x25					; message size = 37 bytes (0x25)
	syscall					


	; Restoring register state
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsp
	pop rdi
	pop rsi
	pop rbx
	pop rdx
	pop rcx
	pop rax


