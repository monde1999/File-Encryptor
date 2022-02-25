# File-Encryptor

## In console application,
### To encrypt:
      fileencryptor /encrypt file
### To decrypt:
      fileencryptor /decrypt file
      
-> You can try encrypting/decrypting the sample files in bin/Debug folder.
      
-> The default encrypt/decrypt function uses session key in default. If you don't want a session key, edit the main() function: instead of encrypt2() or decrypt2(), use encrypt() and decrypt().

-> This program uses AESManaged Symmetric Algorithm. If you want to use other cipher algorithm, also update or change the key byte length.
