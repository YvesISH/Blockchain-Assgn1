#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define MAX_DATA_SIZE 256
#define HASH_SIZE 32

typedef struct Block {
    int index;
    time_t timestamp;
    char data[MAX_DATA_SIZE];
    unsigned char prev_hash[HASH_SIZE];
    unsigned char hash[HASH_SIZE];
} Block;

void calculate_hash(Block *block) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();
    md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, &block->index, sizeof(int));
    EVP_DigestUpdate(mdctx, &block->timestamp, sizeof(time_t));
    EVP_DigestUpdate(mdctx, block->data, strlen(block->data));
    EVP_DigestUpdate(mdctx, block->prev_hash, HASH_SIZE);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    memcpy(block->hash, md_value, HASH_SIZE);

    EVP_MD_CTX_free(mdctx);
}

int validate_chain(Block *blockchain, int size) {
    for (int i = 1; i < size; i++) {
        Block *current_block = &blockchain[i];
        Block *previous_block = &blockchain[i-1];

        unsigned char temp_hash[HASH_SIZE];
        memcpy(temp_hash, current_block->hash, HASH_SIZE);

        calculate_hash(current_block);

        if (memcmp(temp_hash, current_block->hash, HASH_SIZE) != 0) {
            printf("Block %d has been tampered with.\n", i);
            return 0;
        }

        if (memcmp(current_block->prev_hash, previous_block->hash, HASH_SIZE) != 0) {
            printf("Block %d's previous hash doesn't match Block %d's hash.\n", i, i-1);
            return 0;
        }
    }
    return 1;
}

void add_block(Block *blockchain, int *size, const char *data) {
    Block new_block;
    new_block.index = *size;
    new_block.timestamp = time(NULL);
    strncpy(new_block.data, data, MAX_DATA_SIZE);
    new_block.data[MAX_DATA_SIZE - 1] = '\0';

    if (*size > 0) {
        memcpy(new_block.prev_hash, blockchain[*size - 1].hash, HASH_SIZE);
    } else {
        memset(new_block.prev_hash, 0, HASH_SIZE);
    }

    calculate_hash(&new_block);
    blockchain[*size] = new_block;
    (*size)++;
}

void print_block(Block *block) {
    printf("Block #%d\n", block->index);
    printf("Timestamp: %s", ctime(&block->timestamp));
    printf("Data: %s\n", block->data);
    printf("Previous Hash: ");
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", block->prev_hash[i]);
    }
    printf("\nHash: ");
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", block->hash[i]);
    }
    printf("\n\n");
}

int main() {
    Block blockchain[100];
    int size = 0;

    add_block(blockchain, &size, "Genesis Block");
    add_block(blockchain, &size, "Second Block");
    add_block(blockchain, &size, "Third Block");

    for (int i = 0; i < size; i++) {
        print_block(&blockchain[i]);
    }

    if (validate_chain(blockchain, size)) {
        printf("Blockchain is valid.\n");
    } else {
        printf("Blockchain is invalid.\n");
    }

    return 0;
}