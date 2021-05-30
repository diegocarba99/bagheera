BITS 64

SECTION .text
global main

main:
    push rax ; guardamos registros
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    mov rax,1 ; sys_write
    mov rdi,1 ; stdout
    lea rsi,[rel $+frase-$] ; frase
    mov rdx,[rel $+len-$] ; len
    syscall

    pop r11 ; restauramos registros
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax


frase: db "Ejecutando payload",33,10
len : dd 20
