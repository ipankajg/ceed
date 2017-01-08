BITS 32
GLOBAL _start
SECTION .text
_start:
itoa:

    ; eax must contain the number that needs to be converted.

    ; ebx must point to a buffer that would store the converted string.
    ; The buffer must have at least 12 bytes to contain maximum 4-byte number
    ; including minus sign.
    
    push ebp		
    mov ebp, esp
    sub esp, 4	                ; Allocate 4 bytes for string length

    add ebx, 11                 ; Mov to end of buffer
    mov byte [ebx], 0	        ; Put \0 or NULL at the end
    mov ecx, 10                 ; Divisor
    mov dword [ebp - 4], 0	    ; ebp-4 will contain string length

.checknegative:
    xor edi, edi
    cmp eax, 0
    jge .divloop
    neg eax
    mov edi, 1

.divloop:
    xor edx, edx		        ; Zero out edx (remainder is in edx after idiv)
    idiv ecx		            ; Divide eax by ecx
    add edx, 0x30	            ; Add 0x30 to the remainder to get ASCII value
    dec ebx		                ; Move the pointer backwards in the buffer
    mov byte [ebx], dl	        ; Move the character into the buffer
    inc dword [ebp - 4]	        ; Increase the length
    
    cmp eax, 0                  ; Was the result zero?
    jnz .divloop                ; No it wasn't, keep looping

.minussign:
    cmp edi, 1
    jne .done

    dec ebx
    mov byte [ebx], 0x2d
    inc dword [ebp - 4]	        ; Increase the length

.done:
    mov ecx, ebx		        ; ecx points to the beginning of the string
    mov edx, [ebp - 4]          ; ebp-4 contains the length - move it into edx

    mov esp, ebp		        ; Clean up our stack
    pop ebp
    ret



atoi:

    ; ebx must point to the input buffer that is NULL terminated.
    
    push ebp
    mov ebp, esp
    sub esp, 4

.init:
    ; Initialize variables and registers
    xor edi, edi                ; Used as counter
    mov ecx, 10	                ; Used as multiplier
    xor eax, eax                ; Returns result
    xor edx, edx                ; Temporary 
    mov dword [ebp - 4], 0      ; Store result

.checknegative:
    xor esi, esi                ; Used to represent negative numbers
    mov dl, [ebx + edi]         ; Select the character
    cmp dl, 0x2d                ; Check if this is - sign
    jne .multiplyLoop
    mov esi, 1                  ; esi = 1 represents negative numers
    inc edi                     ; mov buffer pointer

.multiplyLoop:
    mov eax, [ebp - 4]          ; Get saved value
    mul ecx	                    ; Make this value 10x
    jo  .invalid                ; Jump in case of overflow
    mov dl, [ebx + edi]         ; Select the character
    cmp dl, 0x30                ; Validate character between 0-9
    jl .invalid
    cmp dl, 0x39
    jg .invalid
    sub dl, 0x30                ; Subtract ASCII 48 to get its actual value
    add eax, edx                ; Add new value and 10x old value
    mov [ebp - 4], eax	        ; Save result
    inc edi                     ; Increase the counter
    cmp byte [ebx + edi], 0     ; Have we reached a null terminator?
    je .finish                  ; If yes, we are done.
    cmp byte [ebx + edi], 0xa   ; Have we reached a newline character?
    je .finish                  ; If yes, we are done.
    cmp byte [ebx + edi], 0xd   ; Did we reach a carriage return (in windows)?
    je .finish                  ; If yes, we are done.
    jmp .multiplyLoop           ; Loop back

.finish:
    mov eax, [ebp - 4]          ; Result in eax
    
.minussign:
    cmp esi, 1
    jne .done
    neg eax
    jmp .done

.invalid:
    xor eax, eax

.done:
    mov esp, ebp		        ; clean up our stack
    pop ebp
    ret

