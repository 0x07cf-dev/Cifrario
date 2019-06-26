.data
  welcomeMsg: .asciiz "Welcome. \n"
  ioErrorMsg: .asciiz "Invalid key. \n"

  keyPath: .asciiz "chiave.txt"
  keyBuffer: .space 4

  reverseKeyBuffer: .space 4

  inputPath: .asciiz "messaggio.txt"
  inputBuffer: .space 128

  outputPath: .asciiz "messaggioCifrato.txt"
  outputBuffer: .space 1024

.text
.globl main

main:
  li $v0, 4
  la $a0, welcomeMsg
  syscall

  jal loadInput
  move $t6, $v1

  jal loadKey
  move $t7, $v1

  move $a0, $t6
  move $a1, $t7
  jal encryptInput

endEncrypt:
  # Termine del codice.
  li $v0, 10
  syscall
# Fine.


###############################################################################################################################
## 1) Caricamento del messaggio da cifrare/decifrare in $v1.
###############################################################################################################################
loadInput:
    # Apro il file contenente il messaggio.
  li $v0, 13
  la $a0, inputPath   # name
  li $a1, 0           # flags
  li $a2, 0           # mode
  syscall

  move $t0, $v0

    # Leggo il file.
  li $v0, 14
  move $a0, $t0           # descriptor
  la $a1, inputBuffer     # buffer
  li $a2, 32              # count
  syscall

  la $v1, inputBuffer

    # Chiudo il file.
  li $v0, 16
  move $a0, $t0     # filename
  syscall

  jr $ra

###############################################################################################################################
## 2) Caricamento della chiave di cifratura in $v1.
###############################################################################################################################
loadKey:

  # Apro il file contenente la chiave, ottenendone il descrittore nel registro $v0. (negativo = errore)
  li $v0, 13
  la $a0, keyPath       # percorso del file
  li $a1, 0             # flags (0 = read-only)
  syscall

  blt $v0, $zero, ioError
  move $t0, $v0

  # Leggo il file
  li $v0, 14
  move $a0, $t0         # descrittore del file
  la $a1, keyBuffer     # buffer
  li $a2, 32            # numero di caratteri da leggere
  syscall

  bltz $v0, ioError
  la $v1, keyBuffer

  # Chiudo il file.
  li $v0, 16
  move $a0, $t0
  syscall

  jr $ra

###############################################################################################################################
##  4) Lettura iterativa dei caratteri della chiave con conseguente
##  applicazione dei corrispondenti algoritmi di cifratura. (input = $a0, chiave = $a1).
###############################################################################################################################
encryptInput:
  move $t0, $a0

  lb $t2, 0($a1)  # carico il prossimo carattere della chiave su $t1
  beqz $t2, endEncrypt   # termina il loop una volta raggiunto il carattere finale

  blt $t2, 'A', ioError
  bgt $t2, 'E', ioError

  beq $t2, 'A', encryptA
  beq $t2, 'B', encryptB
  beq $t2, 'C', encryptC
  beq $t2, 'D', encryptD
  beq $t2, 'E', encryptE

  encryptInputNext:
    addi $a1, $a1, 1 # passo al prossimo carattere
    move $a0, $v1 # ogni algoritmo salverà il risultato
    j encryptInput

###############################################################################################################################
##  5) Salvataggio del messaggio cifrato. ()
###############################################################################################################################
saveEncryptedMessage:
  move $t0, $a0

  li $v0, 13
  la $a0, outputPath
  li $a1, 1
  li $a2, 0
  syscall

  move $a0, $v0
  li $v0, 15
  la $a1, outputBuffer
  syscall

  li $v0, 16
  syscall

  jr $ra



Tutti gli algoritmi agiscono su un messaggio in $a0 e NON devono assolutamente modificare il valore del registro $a1 che contiene la chiave di cifratura originale!
################################################################################################################################
##  A) Il codice ASCII standard su 8 bit di ciascun carattere del messaggio di testo viene modificato sommandoci una costante decimale K=4, modulo 256.
##  Ovvero, se cod(X) è la codifica ascii standard decimale di un carattere X del messaggio, la cifratura di X corrisponderà a: (cod(X)+K) mod 256).
##########################################################################################################################
encryptA:
  lb $t4, 0($t0) # carico il prossimo carattere non cifrato su $t3
  beqz $t4, encryptEnd

  addi $t5, $t4, 4
  div $t5, $t5, 256
  sb $t3, 0($t4) # salvo il carattere così cifrato

  addi $t3, $t3, 1 # passo al prossimo carattere
  j encryptA

  encryptEnd:
    move $v1, $t3 # sposto il risultato in $v1.
    j encryptInputNext


################################################################################################################################
##  B) Si applica l’Algoritmo A a tutti i caratteri del messaggio di testo che sono in posizione di indice pari.
##########################################################################################################################
encryptB:

  j encryptInputNext


################################################################################################################################
##  C) Si applica l’Algoritmo A a tutti i caratteri del messaggio di testo che sono in posizione di indice dispari.
##########################################################################################################################
encryptC:

  j encryptInputNext


################################################################################################################################
##  D) Il messaggio viene cifrato invertendo l’ordine dei caratteri del messaggio di  testo.
##########################################################################################################################
encryptD:

  j encryptInputNext


################################################################################################################################
## E) a partire dal primo carattere del messaggio (quello alla posizione 0), il messaggio viene cifrato come una sequenza di stringhe separate da esattamente 1 spazio 
## in cui ciascuna stringa ha la forma “x��?p1��?...��?pk��?, dove x è la  prima occorrenza di ciascun carattere presente nel messaggio, p1...pk sono le posizioni in cui il carattere
## x appare nel messaggio (con p1<...<pk), ed in cui ciascuna posizione è  preceduta dal carattere separatore ‘��?‘ (per distinguere gli elementi della sequenza delle posizioni). 
##########################################################################################################################
encryptE:

  j encryptInputNext
