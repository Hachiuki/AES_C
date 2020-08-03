# AES_C
 Aes encryption/decryption command line program that allows different modes and input files as arguments.
 
 This project was result of my studies to understand AES for schoolworks.
 AES block cipher is referenced from
 https://github.com/kokke/tiny-AES-c/blob/master/aes.c
 
 Supports 128/196/256 bits key length.
 Supported modes: ECB/CBC/CTR/
 
 Usage:

 aes [OPTION]... input_file output_file key_file
 OPTION
 Key length: -1 | -2| -3
 1(default): 128 
 2: 196 
 3: 256
 Mode: -e | -b | -t | -c | -C | -o | -O
 e: ECB (default)
 b: CBC
 t: CTR
 c: CFB-1
 C: CFB-8
 o: OFB-1
 O: OFB-8
 Display help: -h
