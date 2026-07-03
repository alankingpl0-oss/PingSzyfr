; =====================================================================
; Szyfrator XOR w NASM (Linux x86_64) z obsługą hasła jako argumentu
; Pobiera dane z stdin, szyfruje hasłem podanym w argv[1] i pluje na stdout.
; =====================================================================

section .data
    SYS_READ  equ 0
    SYS_WRITE equ 1
    SYS_EXIT  equ 60
    
    STDIN     equ 0
    STDOUT    equ 1
    STDERR    equ 2
    
    BUF_SIZE  equ 1024
    
    ; Komunikat o błędzie, jeśli brakuje argumentu
    usage_msg db "Błąd: Nie podano hasła!", 10, "Użycie: ./szyfrator <haslo>", 10
    usage_len equ $ - usage_msg

section .bss
    buffer    resb BUF_SIZE   ; Bufor na odczytane dane ze stdin
    key_ptr   resq 1          ; Wskaźnik na ciąg tekstowy hasła
    key_len   resq 1          ; Długość hasła w bajtach

section .text
    global _start

_start:
    ; Sprawdzamy liczbę argumentów (argc) z góry stosu
    mov rax, [rsp]
    cmp rax, 2
    jl .err_usage             ; Jeśli argc < 2, oznacza to brak hasła

    ; Pobieramy wskaźnik do argv[1] (hasło)
    mov rsi, [rsp + 16]
    mov [key_ptr], rsi        ; Zapisujemy adres hasła

    ; Obliczamy długość hasła (szukamy bajtu zerowego - null terminator)
    xor rcx, rcx              ; Zerujemy licznik długości
.strlen_loop:
    cmp byte [rsi + rcx], 0
    je .strlen_done
    inc rcx
    jmp .strlen_loop
.strlen_done:
    mov [key_len], rcx        ; Zapisujemy wyliczoną długość hasła

    ; Przygotowanie rejestrów pomocniczych do pętli głównej
    xor r12, r12              ; r12 będzie naszym indeksem wewnątrz hasła (0 .. key_len-1)

.read_loop:
    ; Wywołanie systemowe sys_read
    mov rax, SYS_READ
    mov rdi, STDIN
    mov rsi, buffer
    mov rdx, BUF_SIZE
    syscall

    cmp rax, 0
    jle .exit_success         ; Koniec pliku (EOF) lub błąd odczytu

    mov r13, rax              ; r13 = liczba faktycznie odczytanych bajtów
    xor rbx, rbx              ; rbx = indeks w buforze danych (0 .. r13-1)

.cipher_loop:
    cmp rbx, r13
    je .write_buffer          ; Jeśli przetworzyliśmy cały bufor, idziemy go zapisać

    ; Pobieramy aktualny bajt danych
    mov al, [buffer + rbx]

    ; Pobieramy odpowiedni bajt z hasła
    mov rdi, [key_ptr]        ; rdi = adres bazowy hasła
    mov r9b, [rdi + r12]      ; r9b = bajt hasła na pozycji r12

    ; Operacja XOR
    xor al, r9b
    mov [buffer + rbx], al    ; Zapisujemy zmieniony bajt z powrotem

    ; Inkrementacja indeksów
    inc rbx                   ; Następny bajt danych

    inc r12                   ; Następny bajt hasła
    cmp r12, [key_len]        ; Sprawdzamy, czy doszliśmy do końca hasła
    jne .cipher_loop
    xor r12, r12              ; Jeśli tak, resetujemy indeks hasła na 0
    jmp .cipher_loop

.write_buffer:
    ; Wywołanie systemowe sys_write
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rsi, buffer
    mov rdx, r13              ; Wypisujemy dokładnie tyle bajtów, ile odczytaliśmy
    syscall

    jmp .read_loop

.err_usage:
    ; Wypisanie komunikatu na stderr
    mov rax, SYS_WRITE
    mov rdi, STDERR
    mov rsi, usage_msg
    mov rdx, usage_len
    syscall

    ; Wyjście z programu z kodem błędu 1
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall

.exit_success:
    ; Zakończenie programu z kodem 0
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall