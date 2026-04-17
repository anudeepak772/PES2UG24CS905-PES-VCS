// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <libgen.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Build the full object (header + data)
    const char *type_str = (type == OBJ_BLOB) ? "blob" : 
                           (type == OBJ_TREE) ? "tree" : "commit";
    
    // Determine header size; snprintf with NULL tells us the length
    int header_len = snprintf(NULL, 0, "%s %zu", type_str, len) + 1; // +1 for '\0'
    size_t full_len = header_len + len;
    
    unsigned char *full_obj = malloc(full_len);
    if (!full_obj) return -1;

    sprintf((char *)full_obj, "%s %zu", type_str, len); // Includes the \0
    memcpy(full_obj + header_len, data, len);

    // 2. Compute SHA-256 hash of the FULL object
    compute_hash(full_obj, full_len, id_out);

    // 3. Check if object already exists
    char final_path[256];
    object_path(id_out, final_path, sizeof(final_path));
    if (access(final_path, F_OK) == 0) {
        free(full_obj);
        return 0; // Deduplication success
    }

    // 4. Create shard directory
    char dir_path[256];
    strncpy(dir_path, final_path, sizeof(dir_path));
    char *shard_dir = dirname(dir_path); 
    mkdir(shard_dir, 0755); // Returns -1 if exists, which is fine

    // 5. Write to a temporary file
    char temp_path[270];
    snprintf(temp_path, sizeof(temp_path), "%s/tmp_XXXXXX", shard_dir);
    
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full_obj);
        return -1;
    }

    if (write(fd, full_obj, full_len) != (ssize_t)full_len) {
        close(fd);
        unlink(temp_path);
        free(full_obj);
        return -1;
    }


    // 6. fsync() the file
    fsync(fd);
    close(fd);

    // 7. rename() to final path (Atomic)
    if (rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    // 8. Open and fsync() the shard directory to persist the rename
    int dfd = open(shard_dir, O_RDONLY);
    if (dfd != -1) {
        fsync(dfd);
        close(dfd);
    }

    free(full_obj);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char *full_buf = malloc(file_size);
    if (!full_buf) { fclose(f); return -1; }

    if (fread(full_buf, 1, file_size, f) != (size_t)file_size) {
        free(full_buf); fclose(f); return -1;
    }
    fclose(f);
    
    // 4. Verify integrity (Before parsing, ensure data isn't corrupt)
    ObjectID actual_id;
    compute_hash(full_buf, file_size, &actual_id);
    if (memcmp(id->hash, actual_id.hash, HASH_SIZE) != 0) {
        free(full_buf); return -1;
    }

    // 3. Parse the header to extract type and find start of data
    unsigned char *null_byte = memchr(full_buf, '\0', file_size);
    if (!null_byte) { free(full_buf); return -1; }

    if (strncmp((char *)full_buf, "blob", 4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char *)full_buf, "tree", 4) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char *)full_buf, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else { free(full_buf); return -1; }

    // 5 & 6. Allocate buffer, copy data portion, and set outputs
    size_t header_len = (null_byte - full_buf) + 1;
    size_t data_len = file_size - header_len;

    void *payload = malloc(data_len);
    if (!payload) { free(full_buf); return -1; }

    memcpy(payload, full_buf + header_len, data_len);
    
    *data_out = payload;
    *len_out = data_len;

    free(full_buf); // Clean up the raw file buffer
    return 0;
}
