.data
  error_io_msg: .asciiz "Si e' verificato un errore durante un'operazione di I/O. \n"
  error_key_msg: .asciiz "La chiave di cifratura puo' contenere solamente i caratteri 'A', 'B', 'C', 'D', 'E'. \n"

  key_path: .asciiz "chiave.txt"
  key_buffer: .word 1

  plaintext_path: .asciiz "messaggio.txt"
  encrypted_path: .asciiz "messaggioCifrato.txt"
  decrypted_path: .asciiz "messaggioDecifrato.txt"

  input_buffer: .space 512
  output_buffer: .space 512
  enum_chars: .space 256

.text
.globl main

main:
  la $a0, plaintext_path
  jal read_file
  jal read_key

  move $a0, $s0
  move $a1, $s2
  jal encrypt_loop

  la $a0, encrypted_path
  jal write_file

  # fine ciclo cifratura; inizio decifratura

  la $a0, encrypted_path
  jal read_file
  jal read_key

  move $a0, $s0
  move $a1, $s2
  jal decrypt_loop

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
  li $a2, 128                                   # numero di caratteri da leggere
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
encrypt_loop:
  lb $t0, 0($a1)                                # $t0 = prossimo carattere della chiave
  beq $t0, 0x00, encrypt_loop_exit              # termina il ciclo una volta raggiunto il carattere nullo
  blt $t0, 0x41, error_key
  bgt $t0, 0x45, error_key

  la $s7, output_buffer
  beq $t0, 0x41, encrypt_a
  beq $t0, 0x42, encrypt_b
  beq $t0, 0x43, encrypt_c
  beq $t0, 0x44, encrypt_d
  beq $t0, 0x45, encrypt_e
encrypt_loop_next:
  move $a0, $v0
  addi $a1, $a1, 1                              # incremento l'indirizzo della chiave
  j encrypt_loop
encrypt_loop_exit:
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
decrypt_loop:
  lb $t0, 0($a1)
  beq $t0, 0x00, decrypt_loop_exit              # si assuma che la chiave sia semanticamente valida poiché
                                                # il controllo è eseguito durante la fase di cifratura
  la $s7, output_buffer
  beq $t0, 0x41, decrypt_a
  beq $t0, 0x42, decrypt_b
  beq $t0, 0x43, decrypt_c
  beq $t0, 0x44, decrypt_d
  beq $t0, 0x45, decrypt_e
decrypt_loop_next:
  move $a0, $v0
  addi $a1, $a1, 1                              # incremento l'indirizzo della chiave
  j encrypt_loop
decrypt_loop_exit:
  jr $ra


###############################################################################################################################


encrypt_a:
  li $a2, 0
  li $a3, 0
_encrypt_a:
  beq $a3, $zero, ea_loop
  addi $a3, $a3, -1
  addi $a0, $a0, 1
  lb $t0, 0($a0)
  sb $t0, 0($s7)
  addi $s7, $s7, 1                              # ignora $a3 caratteri

  ea_loop:
    lb $t0, 0($a0)                              # $t0 = prossimo carattere del messaggio
    beq $t0, 0x00, ea_loop_exit                 # termina il ciclo una volta raggiunto il carattere nullo

    addi $t0, $t0, 4
    div $t0, $t0, 256
    mfhi $t0                                    # $t0 = ($t0 + 4) % 256
    sb $t0, 0($s7)                              # salvo il carattere cifrato su output_buffer

    addi $a0, $a0, 1                            # passo al prossimo carattere
    addi $s7, $s7, 1                            # incremento l'indirizzo del buffer

    beq $a2, $zero, ea_loop_skip
    lb $t0, 0($a0)
    sb $t0, 0($s7)
    add $a0, $a0, $a2
    add $s7, $s7, $a2
  ea_loop_skip:
    j ea_loop
  ea_loop_exit:
    la $v0, output_buffer                       # $v0 = indirizzo del messaggio cifrato
  j encrypt_loop_next

encrypt_b:
  li $a2, 1
  li $a3, 0
  j _encrypt_a

encrypt_c:
  li $a2, 1
  li $a3, 1
  j _encrypt_a

encrypt_d:
  li $t0, 0                                     # i
  addi $t1, $s1, -1                             # j = str_len - 1

  ed_loop:
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

    ble $t0, $t1, ed_loop
    la $v0, output_buffer
  j encrypt_loop_next

encrypt_e:
  li $t0, 0       # i
  li $t1, 0       # j
  li $t2, 0       # k
  la $t3, enum_chars

  ee_loop:
    bge $t0, $s1, ee_loop_exit                   # if i >= str_len exit loop
    move $t1, $t0                               # j = i
    add $t2, $a0, $t0                           # $t2 = &str[i]
    lb $a2, 0($t2)                              # $a2 = str[i]

    add $t4, $t3, $a2                           # $t4 = &enum_chars + &str[i]
    lb $s4, 0($t4)
    beq $a2, $s4, ee_loop_skip                   # se il carattere è giÃ  stato visitato, salta al prossimo
    sb $a2, 0($t4)                              # altrimenti inseriscilo in enum_chars
    li $t4, 0
    li $s4, 0                                   # ripristino i registri
    sb $a2, 0($s7)
    addi $s7, $s7, 1
    li $t2, 0

    char_loop:
      bge $t1, $s1, char_loop_exit              # if j >= str_len exit loop
      add $t4, $s0, $t1                         # $t4 = &str[j]
      lb $a3, 0($t4)                            # $a3 = str[j]
      bne $a2, $a3, char_loop_skip              # if str[i] != str[j] salta al prossimo

      move $s6, $t1                             # j viene copiato
      li $t4, 45
      sb $t4, 0($s7)
      addi $s7, $s7, 1                          # aggiungo il carattere "-"

      push_loop:
        addi $sp, $sp, -1
        div $t4, $t1, 10
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

  ee_loop_skip:
    addi $t0, $t0, 1                            # i++
    j ee_loop
  ee_loop_exit:
    la $v0, output_buffer
    li $t0, 0

    count_loop:
      add $t1, $v0, $t0
      lb $t2, 0($t1)
      beq $t2, 0x00, count_loop_exit
      addi $t0, $t0, 1
      j count_loop
    count_loop_exit:
      move $s1, $t0                             # E non preserva la lunghezza della stringa, perciò è da aggiornare
    j encrypt_loop_next


###############################################################################################################################


decrypt_a:
  li $a2, 0
  li $a3, 0
_decrypt_a:
  beq $a3, $zero, da_loop
  addi $a3, $a3, -1
  addi $a0, $a0, 1
  lb $t0, 0($a0)
  sb $t0, 0($s7)
  addi $s7, $s7, 1                              # ignora $a3 caratteri

  da_loop:
    lb $t0, 0($a0)                              # $t0 = prossimo carattere del messaggio
    beq $t0, 0x00, da_loop_exit                 # termina il ciclo una volta raggiunto il carattere nullo

    addi $t0, $t0, -4
    div $t0, $t0, 256
    mfhi $t0                                    # $t0 = ($t0 - 4) % 256
    sb $t0, 0($s7)                              # salvo il carattere decifrato su output_buffer

    addi $a0, $a0, 1                            # passo al prossimo carattere
    addi $s7, $s7, 1                            # incremento l'indirizzo del buffer

    beq $a2, $zero, da_loop_skip
    lb $t0, 0($a0)
    sb $t0, 0($s7)
    add $a0, $a0, $a2
    add $s7, $s7, $a2
  da_loop_skip:
    j da_loop
  da_loop_exit:
    la $v0, output_buffer
  j decrypt_loop_next

decrypt_b:
    li $a2, 1
    li $a3, 0
    j _decrypt_a

decrypt_c:
    li $a2, 1
    li $a3, 1
    j _decrypt_a

decrypt_d:
  li $t0, 0                                     # i
  addi $t1, $s1, -1                             # j = str_len - 1

  dd_loop:
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

    ble $t0, $t1, dd_loop
    la $v0, output_buffer
  j decrypt_loop_next

decrypt_e:
  # effimeri attimi di sofferenza mi separano dalla celestiale salvezza

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
