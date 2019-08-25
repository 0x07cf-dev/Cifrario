.data
  error_io_msg: .asciiz "Si e' verificato un errore durante un'operazione di I/O. \n"
  error_key_msg: .asciiz "La chiave di cifratura puo' contenere solamente i caratteri 'A', 'B', 'C', 'D', 'E'. \n"

  key_path: .asciiz "chiave.txt"
  key_buffer: .space 5

  plaintext_path: .asciiz "messaggio.txt"
  encrypted_path: .asciiz "messaggioCifrato.txt"
  decrypted_path: .asciiz "messaggioDecifrato.txt"

  input_buffer: .space 2633                     # la lunghezza del messaggio originale (128) puo' essere modificata soltanto
  output_buffer: .space 2633                    # dall'algoritmo E: nel caso degenere in cui il messaggio sia composto di soli caratteri differenti,
                                                # dopo quattro ipotetiche iterazioni dell'algoritmo, si avrebbero (10*4 + 90*5 + 28*6)*4 + 1 = 2633 caratteri
  temp_buffer: .space 512
  enum_chars: .space 256

.text
.globl main

main:
cipher:
  la $a0, plaintext_path
  li $a2, 128                                   # caratteri da leggere
  jal read_file
  jal read_key

  move $a0, $s0
  move $a1, $s2
  jal cipher_loop

  la $a0, encrypted_path
  jal write_file

decipher:
  la $a0, encrypted_path
  li $a2, 2048
  jal read_file
  jal read_key

  move $a0, $s0
  move $a1, $s2
  jal decipher_loop

  la $a0, decrypted_path
  jal write_file

exit:
  li $v0, 10
  syscall


###############################################################################################################################
## 1) Lettura del messaggio da cifrare/decifrare; indirizzo salvato in $s0, lunghezza del messaggio in $s1.
###############################################################################################################################
read_file:
    # Apro il file.
  li $v0, 13
  li $a1, 0                                     # flags (0 = read-only)
  syscall
  blt $v0, $zero, error_io

    # Leggo il file.
  move $a0, $v0                                 # descrittore del file
  li $v0, 14
  la $a1, input_buffer                          # buffer
  syscall
  bltz $v0, error_io

  la $s0, input_buffer                          # $s0 = indirizzo del messaggio letto
  move $s1, $v0                                 # $s1 = lunghezza del messaggio letto

    # Chiudo il file.
  li $v0, 16
  syscall

  jr $ra

###############################################################################################################################
## 2) Lettura della chiave di cifratura; indirizzo salvato in $s2, lunghezza della chiave in $s3.
###############################################################################################################################
read_key:
  bne $s2, $zero, reverse_key                   # se la chiave è già stata caricata, allora siamo in fase di decifratura
    # Apro il file.
  li $v0, 13
  la $a0, key_path                              # percorso del file
  li $a1, 0                                     # flags (0 = read-only)
  syscall
  blt $v0, $zero, error_io

    # Leggo il file.
  move $a0, $v0                                 # descrittore del file
  li $v0, 14
  la $a1, key_buffer                            # buffer
  li $a2, 4                                     # numero di caratteri da leggere
  syscall
  bltz $v0, error_io

  la $s2, key_buffer                            # $s2 = indirizzo della chiave letta
  move $s3, $v0                                 # $s3 = lunghezza della chiave letta

    # Chiudo il file.
  li $v0, 16
  syscall

  jr $ra

reverse_key:
  li $t0, 0
  addi $t1, $s3, -1

  reverse_key_loop:
    add $t2, $s2, $t0
    add $t3, $s2, $t1

    lb $t4, 0($t2)
    lb $t5, 0($t3)

    add $t6, $s2, $t0
    add $t7, $s2, $t1

    sb $t4, 0($t7)
    sb $t5, 0($t6)

    addi $t0, $t0, 1
    addi $t1, $t1, -1
    ble $t0, $t1, reverse_key_loop

  jr $ra

###############################################################################################################################
##  3) Lettura iterativa dei caratteri della chiave con conseguente
##     applicazione dei corrispondenti algoritmi di cifratura.
###############################################################################################################################
cipher_loop:
  lb $t0, 0($a1)                                # $t0 = prossimo carattere della chiave
  beq $t0, 0x00, cipher_loop_exit               # termina il ciclo una volta raggiunto il carattere nullo
  blt $t0, 0x41, error_key
  bgt $t0, 0x45, error_key

  la $s7, output_buffer
  beq $t0, 0x41, cipher_a
  beq $t0, 0x42, cipher_b
  beq $t0, 0x43, cipher_c
  beq $t0, 0x44, cipher_d
  beq $t0, 0x45, cipher_e
cipher_loop_next:
  move $a0, $v0
  addi $a1, $a1, 1                              # incremento l'indirizzo della chiave
  j cipher_loop
cipher_loop_exit:
  jr $ra

###############################################################################################################################
##  4) Salvataggio del messaggio cifrato/decifrato.
###############################################################################################################################
write_file:
    # Apro il file.
  li $v0, 13
  li $a1, 1
  syscall

    # Scrivo sul file.
  move $a0, $v0
  li $v0, 15
  la $a1, output_buffer
  move $a2, $s1
  syscall

    # Chiudo il file.
  li $v0, 16
  syscall

  jr $ra

###############################################################################################################################
##  5) Applicazione degli algoritmi di decifratura in ordine inverso per risalire al messaggio originale.
###############################################################################################################################
decipher_loop:
  lb $t0, 0($a1)
  beq $t0, 0x00, decipher_loop_exit             # è assunto che la chiave sia semanticamente valida poiché
                                                # il controllo è eseguito durante la fase di cifratura
  la $s7, output_buffer
  beq $t0, 0x41, decipher_a
  beq $t0, 0x42, decipher_b
  beq $t0, 0x43, decipher_c
  beq $t0, 0x44, decipher_d
  beq $t0, 0x45, decipher_e
decipher_loop_next:
  move $a0, $v0
  addi $a1, $a1, 1                              # incremento l'indirizzo della chiave
  j decipher_loop
decipher_loop_exit:
  jr $ra


###############################################################################################################################


cipher_a:
  li $a2, 0                                     # $a2 = numero di caratteri iniziali da ignorare
  li $a3, 0                                     # $a3 = numero di caratteri da ignorare dopo ogni iterazione
  li $s6, 4                                     # $s6 = spostamento del singolo carattere (positivo = cifratura)
_cipher_a:
  beq $a2, $zero, a_loop
  addi $a2, $a2, -1
  addi $a0, $a0, 1
  lb $t0, 0($a0)
  sb $t0, 0($s7)
  addi $s7, $s7, 1                              # ignora $a3 caratteri

  a_loop:
    lb $t0, 0($a0)                              # $t0 = prossimo carattere del messaggio
    beq $t0, 0x00, a_loop_exit                  # termina il ciclo una volta raggiunto il carattere nullo

    add $t0, $t0, $s6
    div $t0, $t0, 256
    mfhi $t0                                    # $t0 = ($t0 +- 4) % 256
    sb $t0, 0($s7)                              # salvo il carattere su output_buffer

    addi $a0, $a0, 1                            # passo al prossimo carattere
    addi $s7, $s7, 1                            # incremento l'indirizzo del buffer

    beq $a3, $zero, a_loop_skip
    lb $t0, 0($a0)
    sb $t0, 0($s7)
    add $a0, $a0, $a3
    add $s7, $s7, $a3
  a_loop_skip:
    j a_loop
  a_loop_exit:
    la $v0, output_buffer                       # $v0 = indirizzo del messaggio cifrato
    bgt $s6, $zero, cipher_loop_next
  j decipher_loop_next

cipher_b:
  li $a2, 0
  li $a3, 1
  li $s6, 4
  j _cipher_a

cipher_c:
  li $a2, 1
  li $a3, 1
  li $s6, 4
  j _cipher_a

cipher_d:
  li $a2, 0
_cipher_d:
  li $t0, 0                                     # i
  addi $t1, $s1, -1                             # j = str_len - 1

  d_loop:
    add $t2, $a0, $t0
    add $t3, $a0, $t1

    lb $t4, 0($t2)                              # $t4 = msg[i]
    lb $t5, 0($t3)                              # $t5 = msg[j]

    add $t6, $s7, $t0
    add $t7, $s7, $t1

    sb $t4, 0($t7)                              # msg[j] = msg[i]
    sb $t5, 0($t6)                              # msg[i] = msg[j]

    addi $t0, $t0, 1                            # i++
    addi $t1, $t1, -1                           # j--

    ble $t0, $t1, d_loop
    la $v0, output_buffer
    beq $a2, $zero, cipher_loop_next
  j decipher_loop_next

cipher_e:
  li $t0, 0       # i
  li $t1, 0       # j
  li $t2, 0       # k
  la $t3, enum_chars
  la $s7, temp_buffer

  e_loop:
    bge $t0, $s1, e_loop_exit                   # if i >= str_len exit loop
    move $t1, $t0                               # j = i
    add $t2, $a0, $t0                           # $t2 = &str[i]
    lb $a2, 0($t2)                              # $a2 = str[i]

    add $t4, $t3, $a2                           # $t4 = &enum_chars + &str[i]
    lb $s4, 0($t4)
    beq $a2, $s4, e_loop_skip                   # se il carattere e' gia' stato visitato, salta al prossimo
    sb $a2, 0($t4)                              # altrimenti inseriscilo in enum_chars
    li $t4, 0
    li $s4, 0                                   # ripristino i registri
    sb $a2, 0($s7)
    addi $s7, $s7, 1
    li $t2, 0

    char_loop:
      bge $t1, $s1, char_loop_exit              # if j >= str_len exit loop
      add $t4, $a0, $t1                         # $t4 = &str[j]
      lb $a3, 0($t4)                            # $a3 = str[j]
      bne $a2, $a3, char_loop_skip              # if str[i] != str[j] salta al prossimo

      move $s6, $t1                             # j viene copiato
      li $t4, 45
      sb $t4, 0($s7)
      addi $s7, $s7, 1                          # aggiungo il carattere "-"

      push_loop:
        addi $sp, $sp, -1
        div $t4, $s6, 10
        mfhi $t4                                # j % 10
        addi $t4, $t4, 48
        sb $t4, 0($sp)
        div $s6, $s6, 10                        # j / 10
        addi $t2, $t2, 1                        # k++
        beq $s6, $zero, pop_loop
        j push_loop

      pop_loop:
        lb $t4, 0($sp)
        sb $t4, 0($s7)
        addi $s7, $s7, 1
        addi $t2, $t2, -1                       # k--
        addi $sp, $sp, 1
        beq $t2, $zero, char_loop_skip
        j pop_loop

    char_loop_skip:
      addi $t1, $t1, 1                          # j++
      j char_loop
    char_loop_exit:
      li $t4, 32
      sb $t4, 0($s7)
      addi $s7, $s7, 1                          # aggiungo il carattere " "

  e_loop_skip:
    addi $t0, $t0, 1                            # i++
    j e_loop
  e_loop_exit:
    li $t0, 0
    la $t1, temp_buffer
    la $t4, output_buffer

    copy_loop:
      add $t2, $t1, $t0
      lb $t3, 0($t2)
      beq $t3, $zero, copy_loop_exit
      add $t5, $t4, $t0
      sb $t3, 0($t5)
      addi $t0, $t0, 1
      j copy_loop
    copy_loop_exit:

    la $v0, output_buffer
    move $s1, $t0                             # E non preserva la lunghezza della stringa, perciò è da aggiornare
    j cipher_loop_next


###############################################################################################################################


decipher_a:
  li $a2, 0
  li $a3, 0
_decipher_a:
  li $s6, -4
  j _cipher_a

decipher_b:
  li $a2, 0
  li $a3, 1
  j _decipher_a

decipher_c:
  li $a2, 1
  li $a3, 1
  j _decipher_a

decipher_d:
  li $a2, 1
  j _cipher_d

decipher_e:
  li $t0, 0                                     # i

  de_loop:
    add $t2, $a0, $t0                           # $t2 = &str[i]
    lb $a2, 0($t2)                              # $a2 = str[i]
    addi $t3, $t2, 1
    lb $a3, 0($t3)                              # $a3 = str[i + 1]

    beq $a2, 0x00, de_loop_exit
    beq $a2, 0x20, de_loop_skip
    beq $a2, 0x2D, de_loop_skip
  de_loop_skip:
    addi $t0, $t0, 1
  de_loop_exit:
  # effimeri attimi di sofferenza mi separano dalla celestiale salvezza
j decipher_loop_next


###############################################################################################################################


error_io:
  li $v0, 4
  la $a0, error_io_msg
  syscall
  j exit

error_key:
  li $v0, 4
  la $a0, error_key_msg
  syscall
  j exit
