#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

// Function to compute the SHA-256 hash using the EVP API
void sha256(const char *input, unsigned char output[EVP_MAX_MD_SIZE], unsigned int *output_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Create a new context
    const EVP_MD *md = EVP_sha256();       // Use SHA-256

    EVP_DigestInit_ex(mdctx, md, NULL);     // Initialize digest
    EVP_DigestUpdate(mdctx, input, strlen(input)); // Hash the input data
    EVP_DigestFinal_ex(mdctx, output, output_len); // Finalize the hash
    EVP_MD_CTX_free(mdctx);  // Free the context
}

void print_hash(unsigned char *hash, unsigned int length) {
    for (unsigned int i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    const char *input = "Blockchain Cryptography";
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    sha256(input, hash, &hash_len);

    printf("SHA-256 hash of '%s':\n", input);
    print_hash(hash, hash_len);

    return 0;
}