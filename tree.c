// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include "index.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
static int build_tree_recursive(const Index *idx, int start, int end, int depth, ObjectID *id_out) {
    Tree tree;
    memset(&tree, 0, sizeof(Tree));

    for (int i = start; i < end; ) {
        const IndexEntry *entry = &idx->entries[i];
        
        // Find if there is a slash in the path after our current directory depth
        char *slash = strchr(entry->path + depth, '/');

        if (slash == NULL) {
            // Case 1: It's a FILE in the current directory
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entry->mode;
            
            // Extract filename only (e.g., "file.txt" from "src/file.txt")
            const char *name_start = entry->path + depth;
            strncpy(te->name, name_start, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0'; // Safety null-termination
            
            memcpy(te->hash.hash, entry->hash.hash, HASH_SIZE);
            i++;
        } else {
            // Case 2: It's a SUBDIRECTORY
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            
            size_t dir_name_len = slash - (entry->path + depth);
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            
            // Copy just the folder name (e.g., "src")
            memcpy(te->name, entry->path + depth, dir_name_len);
            te->name[dir_name_len] = '\0';

            // Find all subsequent index entries that belong in this same folder
            int group_end = i + 1;
            while (group_end < end) {
                if (strncmp(idx->entries[group_end].path + depth, te->name, dir_name_len) != 0 ||
                    idx->entries[group_end].path[depth + dir_name_len] != '/') {
                    break;
                }
                group_end++;
            }

            // Recurse: build the sub-tree and store its hash in the current tree entry
            // depth + dir_name_len + 1 skips "folder_name/"
            if (build_tree_recursive(idx, i, group_end, depth + dir_name_len + 1, &te->hash) != 0) {
                return -1;
            }
            i = group_end; // Skip all files we just processed in that sub-tree
        }
    }

    // Serialize this tree level and write it to the object store
    void *data = NULL;
    size_t len = 0;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;
    
    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}
int tree_from_index(ObjectID *id_out) {
    Index idx;
    
    // 1. Load the staged files
    if (index_load(&idx) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        return -1;
    }
    
    // 2. If nothing is staged, we can't build a tree
    if (idx.count == 0) {
        return -1;
    }

    // 3. Mandatory: Sort the index entries by path.
    // This ensures that all files in "src/" are adjacent, allowing the
    // recursive function to group them correctly.
    for (int i = 0; i < idx.count - 1; i++) {
        for (int j = 0; j < idx.count - i - 1; j++) {
            if (strcmp(idx.entries[j].path, idx.entries[j+1].path) > 0) {
                IndexEntry temp = idx.entries[j];
                idx.entries[j] = idx.entries[j+1];
                idx.entries[j+1] = temp;
            }
        }
    }

    // 4. Start building from the root (depth 0)
    return build_tree_recursive(&idx, 0, idx.count, 0, id_out);
}
