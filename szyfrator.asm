; =====================================================================
; Ulepszony Szyfrator XOR w NASM (Linux x86_64)
; Użycie: ./szyfrator <haslo> [plik_wej] [plik_wyj]
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
    
    usage_msg db "Błąd: Brakujące argumenty!", 10
              db "Użycie: ./szyfrator <haslo> [plik_wej] [plik_wyj]", 10
              db "Jeśli nie podasz plików, program użyje stdin/stdout.", 10
    usage_len equ $ - usage_msg

    err_in_msg db "Błąd: Nie można otworzyć pliku wejściowego!", 10
    err_in_len equ $ - err_in_msg

    err_out_msg db "Błąd: Nie można utworzyć/otworzyć pliku wyjściowego!", 10
    err_out_len equ $ - err_out_msg

section .bss
    buffer    resb BUF_SIZE   ; Bufor na odczytane dane
    key_ptr   resq 1          ; Wskaźnik na ciąg tekstowy hasła
    key_len   resq 1          ; Długość hasła w bajtach
    fd_in     resq 1          ; Deskryptor pliku wejściowego
    fd_out    resq 1          ; Deskryptor pliku wyjściowego

section .text
    global _start

_start:
    ; Sprawdzamy liczbę argumentów (argc) z góry stosu
    mov rax, [rsp]
    cmp rax, 2
    jl .err_usage             ; Jeśli argc < 2, to nawet hasła nie ma

    ; Domyślnie ustawiamy stdin i stdout
    mov qword [fd_in], STDIN
    mov qword [fd_out], STDOUT

    ; Pobieramy wskaźnik do argv[1] (hasło)
    mov rsi, [rsp + 16]
    mov [key_ptr], rsi

    ; Obliczamy długość hasła
    xor rcx, rcx
.strlen_loop:
    cmp byte [rsi + rcx], 0
    je .strlen_done
    inc rcx
    jmp .strlen_loop
.strlen_done:
    mov [key_len], rcx

    ; Sprawdzamy czy podano plik wejściowy (argc >= 3)
    mov rax, [rsp]
    cmp rax, 3
    jl .init_cipher_loop      ; Brak dodatkowych plików, jedziemy na stdin/stdout

    ; Otwieramy plik wejściowy (argv[2])
    mov rdi, [rsp + 24]       ; rdi = argv[2]
    mov rax, SYS_OPEN
    mov rsi, O_RDONLY
    xor rdx, rdx              ; Brak flag uprawnień przy odczycie
    syscall
    cmp rax, 0
    jl .err_input_file
    mov [fd_in], rax          ; Zapisujemy otrzymany deskryptor

    ; Sprawdzamy czy podano plik wyjściowy (argc >= 4)
    mov rax, [rsp]
    cmp rax, 4
    jl .init_cipher_loop      ; Brak pliku wyjściowego, wynik idzie na stdout

    ; Otwieramy/Tworzymy plik wyjściowy (argv[3])
    mov rdi, [rsp + 32]       ; rdi = argv[3]
    mov rax, SYS_OPEN
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0644o            ; Uprawnienia rw-r--r-- (w ósemkowym NASM dopisek 'o')
    syscall
    cmp rax, 0
    jl .err_output_file
    mov [fd_out], rax          ; Zapisujemy otrzymany deskryptor

.init_cipher_loop:
    xor r12, r12              ; r12 = indeks wewnątrz hasła (0 .. key_len-1)

.read_loop:
    ; Wywołanie systemowe sys_read z fd_in
    mov rax, SYS_READ
    mov rdi, [fd_in]
    mov rsi, buffer
    mov rdx, BUF_SIZE
    syscall

    cmp rax, 0
    jle .close_files          ; Koniec pliku (EOF) lub błąd

    mov r13, rax              ; r13 = liczba odczytanych bajtów
    xor rbx, rbx              ; rbx = indeks w buforze danych

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
    jne .cipher_loop
    xor r12, r12
    jmp .cipher_loop

.write_buffer:
    ; Wywołanie systemowe sys_write do fd_out
    mov rax, SYS_WRITE
    mov rdi, [fd_out]
    mov rsi, buffer
    mov rdx, r13
    syscall

    jmp .read_loop

.close_files:
    ; Zamykamy plik wejściowy, jeśli nie był to stdin
    cmp qword [fd_in], STDIN
    je .close_output
    mov rax, SYS_CLOSE
    mov rdi, [fd_in]
    syscall

.close_output:
    ; Zamykamy plik wyjściowy, jeśli nie był to stdout
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
    ; Jeśli otwarliśmy wcześniej plik wejściowy, pasuje go zamknąć przed wywaleniem
    cmp qword [fd_in], STDIN
    je .print_err_out
    mov rbx, rax              ; Zachowaj kod błędu
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