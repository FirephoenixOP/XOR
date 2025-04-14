# Memory-XOR Encryption/Decryption Program

This is a simple program to perform file encryption and decryption using XOR operations with a key, utilizing multiple threads for parallel processing. It also implements a checksum mechanism using SHA-256 to ensure file integrity.

## Features

- **XOR-based Encryption/Decryption**: The program uses XOR with a key file for encryption and decryption.
- **Multi-threading Support**: The program uses multiple threads to process the file in parallel, improving performance for large files.
- **SHA-256 Checksum**: After encryption or decryption, a SHA-256 checksum of the file is calculated and can be verified during decryption to ensure data integrity.
- **Password Protection**: A simple password prompt is added to ensure the user has the correct credentials before proceeding with the operation.

## Requirements

Before building the program, ensure the following libraries are installed:

- **OpenSSL**: For SHA-256 hashing.
- **pthread**: For multi-threading support.

### Dependencies

- OpenSSL (`libssl-dev`)
- pthread (`libpthread`)

On a Debian-based system (like Ubuntu), you can install the necessary dependencies using:

```bash
sudo apt-get install libssl-dev libpthread-stubs0-dev
```

### Compilation 

To compile the program with all warnings as errors (for strict checking), use the following gcc command:
```bash
gcc -Wall -Wextra -Werror -g -o xor_program xor_program.c -lssl -lcrypto -pthread
```

Precompiled Binary
A precompiled version of the program for Linux AMD 64 architecture is available for download in the [release](https://github.com/FirephoenixOP/XOR/releases) section of this repository. You can download the file and run it directly without needing to compile it yourself.

### Usage

```bash
./xor_program <input_file> <output_file> <key_file> <-e | -d> [-t thread_count]
```

- **<input_file>:** The file to encrypt or decrypt.
- **<output_file>:** The output file where the encrypted or decrypted content will be saved.
- **<key_file>:** The file containing the key for encryption/decryption.
- **<-e | -d>:** -e for encryption, -d for decryption.
- **[-t thread_count] (optional):** Number of threads to use for parallel processing (default: 4).

### Example

Encrypt a file:
```bash
./xor_encryption input.txt encrypted.txt key.txt -e -t 8
```
When prompted for Password
```bash
pass123
```

Decrypt a file:
```bash
./xor_encryption encrypted.txt output.txt key.txt -d -t 8
```
When prompted for Password
```bash
pass123
```
