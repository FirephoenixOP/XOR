#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <ctype.h>

int DEFAULT_THREADS = 4;
// struct for multi-threading
typedef struct {
    unsigned char *data;
    int key_fd;
    size_t start;
    size_t end;
    size_t key_len;
} ThreadArgs;                        


// XOR main logic, using key position to avoid loading full key in memory
void *xor_thread(void *arg) {                               
    ThreadArgs *args = (ThreadArgs *)arg;
    for (size_t i = args->start; i < args->end; i++) {
        size_t key_pos = i % args->key_len;
        unsigned char key_byte;
        ssize_t r = pread(args->key_fd, &key_byte, 1, key_pos);
        if (r != 1) {
            perror("Failed to read key byte");
            pthread_exit(NULL);
        }
        args->data[i] ^= key_byte;
    }
    pthread_exit(NULL);
}

// chaning bits to 0 to permanent delete them

void secure_zero(unsigned char *data, size_t len) {
    volatile unsigned char *p = data;
    for (size_t i = 0; i < len; i++) {
        *p++ = 0;
    }
}

int password_prompt() {
    char input[64];
    printf("Enter password to proceed: ");
    if (!fgets(input, sizeof(input), stdin)) return 0;
    input[strcspn(input, "\n")] = 0;
    return strcmp(input, "pass123") == 0;
}

void checksum(unsigned char *data, size_t len, unsigned char *hash_out) {
    SHA256(data, len, hash_out);
}

void print_hash(unsigned char *hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <input> <output> <key> <-e | -d> [-t thread_count]\n", argv[0]);
        return 1;
    }

    char *input_file = argv[1];
    char *output_file = argv[2];
    char *key_file = argv[3];
    int decrypt_mode = strcmp(argv[4], "-d") == 0;

    int thread_count = DEFAULT_THREADS;

    // Optional thread count
    
    if (argc >= 7 && strcmp(argv[5], "-t") == 0) {
        thread_count = atoi(argv[6]);
        if (thread_count <= 0) {
            fprintf(stderr, "Invalid thread count, defaulting to %d.\n", DEFAULT_THREADS);
            thread_count = DEFAULT_THREADS;
        }
    }

    if (!password_prompt()) {
        fprintf(stderr, "Authentication failed!\n");
        return 1;
    }

    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        perror("Input file");
        return 1;
    }

    int key_fd = open(key_file, O_RDONLY);
    if (key_fd < 0) {
        perror("Key file");
        fclose(in_fp);
        return 1;
    }

    off_t key_len_off = lseek(key_fd, 0, SEEK_END);
    if (key_len_off <= 0)  {
        perror("Invalid key length");
        close(key_fd);
        fclose(in_fp);
        return 1;
    }
    size_t key_len = (size_t)key_len_off;

    fseek(in_fp, 0, SEEK_END);
    size_t file_size = ftell(in_fp);
    rewind(in_fp);

    size_t data_size = decrypt_mode ? file_size - SHA256_DIGEST_LENGTH : file_size;

    unsigned char *file_data = malloc(data_size);
    if (!file_data) {
        perror("Memory allocation failed");
        close(key_fd);
        fclose(in_fp);
        return 1;
    }

    size_t bytes_read = fread(file_data, 1, data_size, in_fp);
    if (bytes_read != data_size) {
        fprintf(stderr, "Error: Could not read the entire file.\n");
        free(file_data);
        close(key_fd);
        fclose(in_fp);
        return 1;
    }

    unsigned char file_hash[SHA256_DIGEST_LENGTH];
    if (decrypt_mode) {
        fread(file_hash, 1, SHA256_DIGEST_LENGTH, in_fp);
    }
    fclose(in_fp);

    if (data_size == 0) {
        fprintf(stderr, "Error: Input file is empty.\n");
        free(file_data);
        close(key_fd);
        return 1;
    }
     // Calculate checksum if encrypting
     if (!decrypt_mode) {
        checksum(file_data, data_size, file_hash);
        printf("Encryption successful. SHA-256 checksum: ");
        print_hash(file_hash);
    }

    // Multithreaded XOR
    pthread_t threads[thread_count];
    ThreadArgs thread_args[thread_count];
    size_t chunk_per_thread = (data_size + thread_count - 1) / thread_count;

    for (int i = 0; i < thread_count; i++) {
        size_t start = i * chunk_per_thread;
        size_t end = (i + 1) * chunk_per_thread;
        if (end > data_size) end = data_size;

        thread_args[i] = (ThreadArgs){file_data, key_fd, start, end, key_len};

        if (pthread_create(&threads[i], NULL, xor_thread, &thread_args[i]) != 0) {
            perror("Thread creation failed");
            free(file_data);
            close(key_fd);
            return 1;
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

   
    FILE *out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        perror("Output file");
        free(file_data);
        close(key_fd);
        return 1;
    }

    if (decrypt_mode) {
        unsigned char new_hash[SHA256_DIGEST_LENGTH];
        checksum(file_data, data_size, new_hash);

        if (memcmp(new_hash, file_hash, SHA256_DIGEST_LENGTH) != 0) {
            fprintf(stderr, "Checksum mismatch! File may be corrupted or wrong key.\n");
            fclose(out_fp);
            free(file_data);
            close(key_fd);
            return 1;
        }
        fwrite(file_data, 1, data_size, out_fp);
        printf("Decryption successful. SHA-256 checksum verified: ");
        print_hash(new_hash);
    } else {
        fwrite(file_data, 1, data_size, out_fp);
        fwrite(file_hash, 1, SHA256_DIGEST_LENGTH, out_fp);
    }

    fclose(out_fp);
    secure_zero(file_data, data_size);
    free(file_data);
    close(key_fd);
    return 0;
}
