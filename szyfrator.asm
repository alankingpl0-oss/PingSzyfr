; =====================================================================
; Ulepszony Szyfrator XOR w NASM (Linux x86_64)
; Użycie: ./pszyfr -k <haslo> [-i plik_wej] [-o plik_wyj]
; Jeśli pominiesz -o, odszyfruje "w locie" bezpośrednio na ekran.
; =====================================================================

section .data
    SYS_READ  equ 0
    SYS_WRITE equ 1
    SYS_OPEN  equ 2
    SYS_CLOSE equ 3
    SYS_EXIT  equ 60
    
    STDIN     equ 0
    STDOUT    equ 1
    STDERR    equ 2
    
    O_RDONLY  equ 0
    O_WRONLY  equ 1
    O_CREAT   equ 64
    O_TRUNC   equ 512
    
    BUF_SIZE  equ 1024
    
    usage_msg db "Blad: Brakujace lub niepoprawne argumenty!", 10
              db "PingSzyfr v0.2. Uzycie: ./pszyfr -k <haslo> [-i plik_wej] [-o plik_wyj]", 10
              db "Jesli pominiesz -i lub -o, program uzyje stdin/stdout.", 10
    usage_len equ $ - usage_msg

    err_in_msg db "Blad: Nie mozna otworzyc pliku wejsciowego!", 10
    err_in_len equ $ - err_in_msg

    err_out_msg db "Blad: Nie mozna utworzyc/otworzyc pliku wyjsciowego!", 10
    err_out_len equ $ - err_out_msg

section .bss
    buffer       resb BUF_SIZE   
    key_ptr      resq 1          
    key_len      resq 1          
    in_file_ptr  resq 1          
    out_file_ptr resq 1          
    fd_in        resq 1          
    fd_out       resq 1          

section .text
    global _start

_start:
    mov r12, [rsp]          ; r12 = argc
    cmp r12, 3              
    jl .err_usage

    mov qword [key_ptr], 0
    mov qword [in_file_ptr], 0
    mov qword [out_file_ptr], 0

    mov r13, 1              ; r13 = indeks argv (od 1)

.parse_args:
    cmp r13, r12            
    jge .check_required

    mov r14, [rsp + r13*8 + 8] 
    mov ax, word [r14]         ; Pobieramy dwa pierwsze znaki (np. "-k")

    cmp ax, 0x6b2d          ; "-k"
    je .parse_key
    cmp ax, 0x692d          ; "-i"
    je .parse_in
    cmp ax, 0x6f2d          ; "-o"
    je .parse_out

    inc r13
    jmp .parse_args

.parse_key:
    inc r13                 
    cmp r13, r12
    jge .err_usage          
    mov r15, [rsp + r13*8 + 8]
    mov [key_ptr], r15
    inc r13
    jmp .parse_args

.parse_in:
    inc r13
    cmp r13, r12
    jge .err_usage          
    mov r15, [rsp + r13*8 + 8]
    mov [in_file_ptr], r15
    inc r13
    jmp .parse_args

.parse_out:
    inc r13
    cmp r13, r12
    jge .err_usage          
    mov r15, [rsp + r13*8 + 8]
    mov [out_file_ptr], r15
    inc r13
    jmp .parse_args

.check_required:
    cmp qword [key_ptr], 0
    je .err_usage

    ; Domyślne deskryptory (w razie braku flag -i oraz -o)
    mov qword [fd_in], STDIN
    mov qword [fd_out], STDOUT

    ; Obliczanie długości klucza
    mov rsi, [key_ptr]
    xor rcx, rcx
.strlen_loop:
    cmp byte [rsi + rcx], 0
    je .strlen_done
    inc rcx
    jmp .strlen_loop
.strlen_done:
    mov [key_len], rcx

    ; Obsługa pliku wejściowego
    cmp qword [in_file_ptr], 0
    je .setup_out           

    mov rdi, [in_file_ptr]
    mov rax, SYS_OPEN
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall
    cmp rax, 0
    jl .err_input_file
    mov [fd_in], rax        

.setup_out:
    ; Obsługa pliku wyjściowego
    cmp qword [out_file_ptr], 0
    je .init_cipher_loop    ; Jeśli brak -o, fd_out zostaje jako STDOUT (wypisze na ekran!)

    mov rdi, [out_file_ptr]
    mov rax, SYS_OPEN
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0644o
    syscall
    cmp rax, 0
    jl .err_output_file
    mov [fd_out], rax       

.init_cipher_loop:
    xor r12, r12            ; Indeks wewnątrz hasła

.read_loop:
    mov rax, SYS_READ
    mov rdi, [fd_in]
    mov rsi, buffer
    mov rdx, BUF_SIZE
    syscall

    cmp rax, 0
    jle .close_files        

    mov r13, rax            ; r13 = liczba przeczytanych bajtów
    xor rbx, rbx            ; rbx = pozycja w buforze

.cipher_loop:
    cmp rbx, r13
    je .write_buffer

    mov al, [buffer + rbx]
    mov rdi, [key_ptr]
    mov r9b, [rdi + r12]

    xor al, r9b
    mov [buffer + rbx], al

    inc rbx
    inc r12
    cmp r12, [key_len]
    jne .skip_reset_key
    xor r12, r12
.skip_reset_key:
    jmp .cipher_loop

.write_buffer:
    mov rax, SYS_WRITE
    mov rdi, [fd_out]
    mov rsi, buffer
    mov rdx, r13
    syscall

    jmp .read_loop

.close_files:
    cmp qword [fd_in], STDIN
    je .close_output
    mov rax, SYS_CLOSE
    mov rdi, [fd_in]
    syscall

.close_output:
    cmp qword [fd_out], STDOUT
    je .exit_success
    mov rax, SYS_CLOSE
    mov rdi, [fd_out]
    syscall

.exit_success:
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

.err_usage:
    mov rdi, STDERR
    mov rsi, usage_msg
    mov rdx, usage_len
    jmp .exit_with_error

.err_input_file:
    mov rdi, STDERR
    mov rsi, err_in_msg
    mov rdx, err_in_len
    jmp .exit_with_error

.err_output_file:
    cmp qword [fd_in], STDIN
    je .print_err_out
    mov rbx, rax            
    mov rax, SYS_CLOSE
    mov rdi, [fd_in]
    syscall
.print_err_out:
    mov rdi, STDERR
    mov rsi, err_out_msg
    mov rdx, err_out_len

.exit_with_error:
    mov rax, SYS_WRITE
    syscall
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall