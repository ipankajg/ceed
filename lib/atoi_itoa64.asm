BITS 64
GLOBAL _start
SECTION .text
_start:
itoa:

    ; rax must contain the number that needs to be converted.

    ; rbx must point to a buffer that would store the converted string.
    ; The buffer must have at least 12 bytes to contain maximum 4-byte number
    ; including minus sign.
    
    push rbp		
    mov rbp, rsp
    sub rsp, 8	                ; Allocate 4 bytes for string length

    add rbx, 11                 ; Mov to end of buffer
    mov byte [rbx], 0	        ; Put \0 or NULL at the end
    mov rcx, 10                 ; Divisor
    mov dword [rbp - 8], 0	    ; rbp-8 will contain string length

.checknegative:
    xor rdi, rdi
    cmp rax, 0
    jge .divloop
    neg rax
    mov rdi, 1

.divloop:
    xor rdx, rdx		        ; Zero out rdx (remainder is in rdx after idiv)
    idiv rcx		            ; Divide rax by rcx
    add rdx, 0x30	            ; Add 0x30 to the remainder to get ASCII value
    dec rbx		                ; Move the pointer backwards in the buffer
    mov byte [rbx], dl	        ; Move the character into the buffer
    inc dword [rbp - 8]	        ; Increase the length
    
    cmp rax, 0                  ; Was the result zero?
    jnz .divloop                ; No it wasn't, keep looping

.minussign:
    cmp rdi, 1
    jne .done

    dec rbx
    mov byte [rbx], 0x2d
    inc dword [rbp - 8]	        ; Increase the length

.done:
    mov rcx, rbx		        ; rcx points to the beginning of the string
    mov rdx, [rbp - 8]          ; rbp-4 contains the length - move it into rdx

    mov rsp, rbp		        ; Clean up our stack
    pop rbp
    ret



atoi:

    ; rbx must point to the input buffer that is NULL terminated.
    
    push rbp
    mov rbp, rsp
    sub rsp, 8

.init:
    ; Initialize variables and registers
    xor rdi, rdi                ; Used as counter
    mov rcx, 10	                ; Used as multiplier
    xor rax, rax                ; Returns result
    xor rdx, rdx                ; Temporary 
    mov dword [rbp - 8], 0      ; Store result

.checknegative:
    xor rsi, rsi                ; Used to represent negative numbers
    mov dl, [rbx + rdi]         ; Select the character
    cmp dl, 0x2d                ; Check if this is - sign
    jne .multiplyLoop
    mov rsi, 1                  ; rsi = 1 represents negative numers
    inc rdi                     ; mov buffer pointer

.multiplyLoop:
    mov rax, [rbp - 8]          ; Get saved value
    mul rcx	                    ; Make this value 10x
    jo  .invalid                ; Jump in case of overflow
    mov dl, [rbx + rdi]         ; Select the character
    cmp dl, 0x30                ; Validate character between 0-9
    jl .invalid
    cmp dl, 0x39
    jg .invalid
    sub dl, 0x30                ; Subtract ASCII 48 to get its actual value
    add rax, rdx                ; Add new value and 10x old value
    mov [rbp - 8], rax	        ; Save result
    inc rdi                     ; Increase the counter
    cmp byte [rbx + rdi], 0     ; Have we reached a null terminator?
    je .finish                  ; If yes, we are done.
    cmp byte [rbx + rdi], 0xa   ; Have we reached a newline character?
    je .finish                  ; If yes, we are done.
    cmp byte [rbx + rdi], 0xd   ; Did we reach a carriage return (in windows)?
    je .finish                  ; If yes, we are done.
    jmp .multiplyLoop           ; Loop back

.finish:
    mov rax, [rbp - 8]          ; Result in rax
    
.minussign:
    cmp rsi, 1
    jne .done
    neg rax
    jmp .done

.invalid:
    xor rax, rax

.done:
    mov rsp, rbp		        ; clean up our stack
    pop rbp
    ret

