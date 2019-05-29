.data
  welcome: .asciiz "Welcome. Would you like to encrypt or decrypt a file? (E/D) \n"
  illegalKeyError: .asciiz "Your cipher key is not valid. \n"
  keyname: .asciiz "D:\\Documents\\MIPS\\Cifrario\\chiave.txt"
  keybuffer: .space 4
  inputname: .asciiz "D:\\Documents\\MIPS\\Cifrario\\messaggio.txt"
  inputbuffer: .space 128

.text
.globl main

# WIP
main:
  li $v0, 4
  la $a0, welcome
  syscall

  jal loadKey
  move $a0, $v1
  jal readKey

  jal loadInput

end:
    # Termine del codice.
  li $v0, 10
  syscall

# Caricamento del messaggio da cifrare/decifrare (ret. $v1).
loadInput:
    # Apro il file contenente il messaggio.
  li $v0, 13
  la $a0, inputname   # name
  li $a1, 0           # flags
  li $a2, 0           # mode
  syscall

  move $t0, $v0

    # Leggo il file.
  li $v0, 14
  move $a0, $t0           # descriptor
  la $a1, inputbuffer     # buffer
  li $a2, 32              # count
  syscall

  la $v1, inputbuffer

    # Inserisco il messaggio nello stack allocandovi 128 byte.
  addi $sp, $sp, -128
  sw $v1, 0($sp)

    # Chiudo il file.
  li $v0, 16
  move $a0, $t0     # filename
  syscall

  jr $ra

# Caricamento della chiave di cifratura (ret. $v1).
loadKey:
    # Apro il file contenente la chiave.
  li $v0, 13
  la $a0, keyname   # name
  li $a1, 0         # flags
  li $a2, 0         # mode
  syscall

  move $t0, $v0

    # Leggo il file
  li $v0, 14
  move $a0, $t0     # descriptor
  la $a1, keybuffer    # buffer
  li $a2, 32        # count
  syscall

  la $v1, keybuffer

    # Chiudo il file.
  li $v0, 16
  move $a0, $t0     # filename
  syscall

  jr $ra

# Lettura iterativa dei caratteri della chiave di cifratura (arg. $a0).
readKey:
  move $t0, $a0
  lb $t1, 0($t0)
  li $t2, 'A'     # first allowed
  li $t3, 'E'     # last allowed

  beqz $t1, end
  blt $t1, $t2, illegalKey
  bgt $t1, $t3, illegalKey

  beq $t1, 'A', encryptA
  beq $t1, 'B', encryptB
  beq $t1, 'C', encryptC
  beq $t1, 'D', encryptD
  beq $t1, 'E', encryptE

  add $t0, $t0, 1

  j readKey

illegalKey:
  li $v0, 4
  la $a0, illegalKeyError
  syscall

  jr main

encryptA:
  j readKey
