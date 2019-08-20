.data
  error_ioMsg: .asciiz "Si è verificato un errore. \n"

  key_path: .asciiz "chiave.txt"
  key_addr: .word 1

  msg_path: .asciiz "messaggio.txt"
  msg_addr: .space 128

  output_path: .asciiz "messaggioCifrato.txt"
  output_buffer: .space 512

  enum_chars: .space 256

.text
.globl main

main:
  jal read_input
  jal read_key

  move $a0, $s0
  move $a1, $s2
  jal encrypt_loop
encrypt_end:
  jal write_output

end:
  li $v0, 10
  syscall


###############################################################################################################################
## 1) Lettura del messaggio da cifrare; indirizzo salvato in $s0, lunghezza del messaggio in $s1.
###############################################################################################################################
read_input:
    # Apro il file.
  li $v0, 13
  la $a0, msg_path                              # percorso del file
  li $a1, 0                                     # flags (0 = read-only)
  syscall

  blt $v0, $zero, error_io

    # Leggo il file.
  move $a0, $v0                                 # descrittore del file
  li $v0, 14
  la $a1, msg_addr                              # buffer
  li $a2, 128                                   # numero di caratteri da leggere
  syscall

  bltz $v0, error_io
  la $s0, msg_addr                              # $s0 = indirizzo del messaggio letto
  move $s1, $v0                                 # $s1 = lunghezza del messaggio letto

    # Chiudo il file.
  li $v0, 16
  syscall

  jr $ra

###############################################################################################################################
## 2) Lettura della chiave di cifratura; indirizzo salvato in $s2, lunghezza della chiave in $s3.
###############################################################################################################################
read_key:
    # Apro il file.
  li $v0, 13
  la $a0, key_path                              # percorso del file
  li $a1, 0                                     # flags (0 = read-only)
  syscall

  blt $v0, $zero, error_io

    # Leggo il file
  move $a0, $v0                                 # descrittore del file
  li $v0, 14
  la $a1, key_addr                              # buffer
  li $a2, 4                                     # numero di caratteri da leggere
  syscall

  bltz $v0, error_io
  la $s2, key_addr                              # $s2 = indirizzo della chiave letta
  move $s3, $v0                                 # $s3 = lunghezza della chiave letta

    # Chiudo il file.
  li $v0, 16
  syscall

  jr $ra

###############################################################################################################################
##  3) Lettura iterativa dei caratteri della chiave con conseguente
##     applicazione dei corrispondenti algoritmi di cifratura.
###############################################################################################################################
encrypt_loop:
  lb $t0, 0($a1)                                # $t0 = prossimo carattere della chiave
  beq $t0, 0x00, encrypt_end                    # termina il ciclo una volta raggiunto il carattere nullo
  blt $t0, 0x41, error_io
  bgt $t0, 0x45, error_io

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

###############################################################################################################################
##  4) Salvataggio del messaggio cifrato.
###############################################################################################################################
write_output:
  li $v0, 13
  la $a0, output_path
  li $a1, 1
  syscall

  move $a0, $v0
  li $v0, 15
  la $a1, output_buffer
  move $a2, $s1
  syscall

  li $v0, 16
  syscall

jr $ra


###############################################################################################################################

encrypt_a:
  li $a2, 0
  li $a3, 0
_encrypt_a:
  beq $a3, $zero, a_loop
  addi $a3, $a3, -1
  addi $a0, $a0, 1
  lb $t0, 0($a0)
  sb $t0, 0($s7)
  addi $s7, $s7, 1                              # ignora $a3 caratteri

  a_loop:
    lb $t0, 0($a0)                              # $t0 = prossimo carattere del messaggio
    beq $t0, 0x00, a_loop_exit                  # termina il ciclo una volta raggiunto il carattere nullo

    addi $t0, $t0, 4
    div $t0, $t0, 256
    mfhi $t0                                    # $t0 = ($t0 + 4) % 256
    sb $t0, 0($s7)                              # salvo il carattere cifrato su output_buffer

    addi $a0, $a0, 1                            # passo al prossimo carattere
    addi $s7, $s7, 1                            # incremento l'indirizzo del buffer

    beq $a2, $zero, a_loop_skip
    lb $t0, 0($a0)
    sb $t0, 0($s7)
    add $a0, $a0, $a2
    add $s7, $s7, $a2
  a_loop_skip:
    j a_loop
  a_loop_exit:
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
  move $t0, $zero                               # i
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
j encrypt_loop_next


encrypt_e:
  li $t0, 0       # i
  li $t1, 0       # j
  li $t2, 0       # k
  la $t3, enum_chars

  e_loop:
    bge $t0, $s1, e_loop_exit                   # if i >= str_len exit loop
    move $t1, $t0                               # j = i
    add $t2, $a0, $t0                           # $t2 = &str[i]
    lb $a2, 0($t2)                              # $a2 = str[i]

    add $t4, $t3, $a2                           # $t4 = &enum_chars + &str[i]
    lb $s4, 0($t4)
    beq $a2, $s4, e_loop_skip                   # se il carattere è giÃ  stato visitato, salta al prossimo
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

  e_loop_skip:
    addi $t0, $t0, 1                            # i++
    j e_loop
  e_loop_exit:
    la $v0, output_buffer
    li $t0, 0

    count_loop:
      add $t1, $v0, $t0
      lb $t2, 0($t1)
      beq $t2, 0x00, count_loop_exit
      addi $t0, $t0, 1
      j count_loop
    count_loop_exit:
      move $s2, $t0                             # poiché l'algoritmo E non preserva la lunghezza originale della stringa, essa deve essere aggiornata
j encrypt_loop_next

error_io:
  j end
