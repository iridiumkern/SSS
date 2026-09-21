#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "sss.h"

#define WOTS_W 16
#define WOTS_LOG_W 4

#define WOTS_LEN1 128
#define WOTS_LEN2 3
#define WOTS_LEN 131

#define TREE_HEIGHT 512

// Domain separation prefixes
#define DOMAIN_WOTS    0x01
#define DOMAIN_PRIVATE 0x02
#define DOMAIN_LEAF    0x03
#define DOMAIN_NODE    0x04

typedef unsigned char wots_element[HASH_OUT_SIZE];

typedef struct {
    wots_element element[WOTS_LEN];
} wots_private_key;

typedef struct {
    wots_element element[WOTS_LEN];
} wots_public_key;

typedef struct {
    wots_element element[WOTS_LEN];
} wots_signature;

typedef struct sss_addr_t {
    uint64_t hypertree[2];
    uint64_t log[2];
    uint64_t branch[2];
    uint64_t twig;
    uint64_t leaf;
} sss_addr_t;

typedef struct {
    sss_addr_t address;
    wots_signature wots_sig;
    unsigned char auth_path[TREE_HEIGHT][HASH_OUT_SIZE];
} sss_signature_t;

// Explicit serialization for address to ensure platform-independent byte representation
static void serialize_address(const sss_addr_t *addr, unsigned char *buf) {
    size_t offset = 0;
    for (int i = 0; i < 2; ++i) {
        uint64_t val = addr->hypertree[i];
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    } for (int i = 0; i < 2; ++i) {
        uint64_t val = addr->log[i];
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    } for (int i = 0; i < 2; ++i) {
        uint64_t val = addr->branch[i];
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    } {
        uint64_t val = addr->twig;
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    } {
        uint64_t val = addr->leaf;
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    }
}

static bool domain_hash(uint8_t domain, const void *data1, size_t size1, const void *data2, size_t size2, unsigned char *output) {
    unsigned char buffer[1 + 64 + sizeof(sss_addr_t) + 64 + sizeof(wots_public_key)];
    size_t total = 0;
    
    buffer[total++] = domain;
    if (data1 && size1 > 0) {
        memcpy(buffer + total, data1, size1);
        total += size1;
    }
    if (data2 && size2 > 0) {
        memcpy(buffer + total, data2, size2);
        total += size2;
    }
    
    bool res = sss_sha512(buffer, total, output);
    memset(buffer, 0, total);
    return res;
}

static bool wots_hash(unsigned char *value) {
    unsigned char hash[HASH_OUT_SIZE];
    if (!domain_hash(DOMAIN_WOTS, value, HASH_OUT_SIZE, NULL, 0, hash)) return false;
    memcpy(value, hash, HASH_OUT_SIZE);
    return true;
}

static bool wots_chain(unsigned char *value, size_t steps) {
    for (size_t i = 0; i < steps; ++i) {
        if (!wots_hash(value)) {
            memset(value, 0, 1);
            return false;
        }
    }
    return true;
}

static void wots_message_digits(const unsigned char *message, unsigned char *digits) {
    for (size_t i = 0; i < HASH_OUT_SIZE; ++i) {
        digits[i * 2] = message[i] >> 4;
        digits[i * 2 + 1] = message[i] & 0x0f;
    }
}

static void wots_checksum(const unsigned char *digits, unsigned char *checksum) {
    unsigned int value = 0;
    for (size_t i = 0; i < WOTS_LEN1; ++i) value += WOTS_W - 1 - digits[i];
    for (size_t i = WOTS_LEN2; i > 0; --i) {
        checksum[i - 1] = value & (WOTS_W - 1);
        value >>= WOTS_LOG_W;
    }
}

static void wots_lengths(const unsigned char *message, unsigned char *lengths) {
    wots_message_digits(message, lengths);
    wots_checksum(lengths, lengths + WOTS_LEN1);
}

static bool wots_generate_public(const wots_private_key *private_key, wots_public_key *public_key) {
    if (private_key == NULL || public_key == NULL) return false;
    for (size_t i = 0; i < WOTS_LEN; ++i) {
        memcpy(public_key->element[i], private_key->element[i], HASH_OUT_SIZE);
        if (!wots_chain(public_key->element[i], WOTS_W - 1)) {
            memset(public_key, 0, sizeof(*public_key));
            return false;
        }
    }
    return true;
}

static bool wots_sign(const wots_private_key *private_key, const unsigned char *message, wots_signature *signature) {
    unsigned char lengths[WOTS_LEN];
    if (private_key == NULL || message == NULL || signature == NULL) return false;
    wots_lengths(message, lengths);
    for (size_t i = 0; i < WOTS_LEN; ++i) {
        memcpy(signature->element[i], private_key->element[i], HASH_OUT_SIZE);
        if (!wots_chain(signature->element[i], lengths[i])) {
            memset(signature, 0, sizeof(*signature));
            return false;
        }
    }
    return true;
}

static bool wots_recover_public(const wots_signature *signature, const unsigned char *message, wots_public_key *public_key) {
    unsigned char lengths[WOTS_LEN];
    if (signature == NULL || message == NULL || public_key == NULL) return false;
    wots_lengths(message, lengths);
    for (size_t i = 0; i < WOTS_LEN; ++i) {
        memcpy(public_key->element[i], signature->element[i], HASH_OUT_SIZE);
        if (!wots_chain(public_key->element[i], (WOTS_W - 1) - lengths[i])) {
            memset(public_key, 0, sizeof(*public_key));
            return false;
        }
    }
    return true;
}

static bool sss_ots_generate_private(const unsigned char *master_seed, const sss_addr_t *address, wots_private_key *key) {
    if (master_seed == NULL || address == NULL || key == NULL) return false;
    
    unsigned char serialized_addr[64];
    serialize_address(address, serialized_addr);

    for (size_t i = 0; i < WOTS_LEN; ++i) {
        uint32_t idx = (uint32_t)i;
        unsigned char index_bytes[4];
        for (int b = 0; b < 4; ++b) index_bytes[b] = (idx >> (b * 8)) & 0xFF;

        unsigned char combined_input[64 + 4];
        memcpy(combined_input, serialized_addr, 64);
        memcpy(combined_input + 64, index_bytes, 4);

        if (!domain_hash(DOMAIN_PRIVATE, master_seed, HASH_OUT_SIZE, combined_input, sizeof(combined_input), key->element[i])) {
            memset(key, 0, sizeof(*key));
            return false;
        }
    }
    return true;
}

static bool sss_hash_node(const unsigned char *left, const unsigned char *right, unsigned char *output) {
    unsigned char children[HASH_OUT_SIZE * 2];
    memcpy(children, left, HASH_OUT_SIZE);
    memcpy(children + HASH_OUT_SIZE, right, HASH_OUT_SIZE);
    bool res = domain_hash(DOMAIN_NODE, children, sizeof(children), NULL, 0, output);
    memset(children, 0, sizeof(children));
    return res;
}

static bool sss_leaf_from_address(const unsigned char *master_seed, const sss_addr_t *address, unsigned char *leaf) {
    wots_private_key priv;
    wots_public_key pub;
    if (!sss_ots_generate_private(master_seed, address, &priv)) return false;
    if (!wots_generate_public(&priv, &pub)) {
        memset(&priv, 0, sizeof(priv));
        return false;
    }
    memset(&priv, 0, sizeof(priv));
    bool res = domain_hash(DOMAIN_LEAF, &pub, sizeof(pub), NULL, 0, leaf);
    memset(&pub, 0, sizeof(pub));
    return res;
}

static void sss_address_from_message(const void *message, size_t message_size, sss_addr_t *address) {
    unsigned char hash[HASH_OUT_SIZE];
    sss_sha512(message, message_size, hash);
    memcpy(address, hash, sizeof(sss_addr_t));
}

// Compute a subtree root or node given a starting address and height offset.
// For a fully deterministic stateless tree, we compute nodes recursively or iteratively based on address navigation.
static bool compute_node_at_height(const unsigned char *master_seed, const sss_addr_t *base_address, int height, unsigned char *node_out) {
    if (height == 0) {
        return sss_leaf_from_address(master_seed, base_address, node_out);
    }

    // Left child and right child addresses differ at the bit corresponding to height - 1
    sss_addr_t left_addr = *base_address;
    sss_addr_t right_addr = *base_address;

    // Modify the bit at index (height - 1) across the 512-bit address space
    int bit_idx = height - 1;
    int chunk = bit_idx / 64;
    int bit_in_chunk = bit_idx % 64;

    uint64_t *target_chunk_left = NULL;
    uint64_t *target_chunk_right = NULL;

    if (chunk == 0) { target_chunk_left = &left_addr.leaf; target_chunk_right = &right_addr.leaf; }
    else if (chunk == 1) { target_chunk_left = &left_addr.twig; target_chunk_right = &right_addr.twig; }
    else if (chunk - 2 < 2) { target_chunk_left = &left_addr.branch[chunk - 2]; target_chunk_right = &right_addr.branch[chunk - 2]; }
    else if (chunk - 4 < 2) { target_chunk_left = &left_addr.log[chunk - 4]; target_chunk_right = &right_addr.log[chunk - 4]; }
    else { target_chunk_left = &left_addr.hypertree[chunk - 6]; target_chunk_right = &right_addr.hypertree[chunk - 6]; }

    *target_chunk_left &= ~(1ULL << bit_in_chunk);
    *target_chunk_right |= (1ULL << bit_in_chunk);

    unsigned char left_node[HASH_OUT_SIZE];
    unsigned char right_node[HASH_OUT_SIZE];

    if (!compute_node_at_height(master_seed, &left_addr, height - 1, left_node)) return false;
    if (!compute_node_at_height(master_seed, &right_addr, height - 1, right_node)) return false;

    bool res = sss_hash_node(left_node, right_node, node_out);
    memset(left_node, 0, HASH_OUT_SIZE);
    memset(right_node, 0, HASH_OUT_SIZE);
    return res;
}

bool sss_generate_keypair(unsigned char *master_seed, unsigned char *root) {
    if (master_seed == NULL || root == NULL) return false;
    if (!sss_get512randsecure(master_seed)) return false;

    sss_addr_t zero_addr;
    memset(&zero_addr, 0, sizeof(zero_addr));

    return compute_node_at_height(master_seed, &zero_addr, TREE_HEIGHT, root);
}

bool sss_sign(const unsigned char *master_seed, const void *message, size_t message_size, unsigned char *signature_out) {
    if (master_seed == NULL || message == NULL || signature_out == NULL) return false;

    sss_signature_t *sig = (sss_signature_t *)signature_out;
    unsigned char msg_hash[HASH_OUT_SIZE];

    sss_sha512(message, message_size, msg_hash);
    sss_address_from_message(message, message_size, &sig->address);

    wots_private_key priv;
    if (!sss_ots_generate_private(master_seed, &sig->address, &priv)) return false;

    if (!wots_sign(&priv, msg_hash, &sig->wots_sig)) {
        memset(&priv, 0, sizeof(priv));
        return false;
    }
    memset(&priv, 0, sizeof(priv));

    // Generate genuine authentication path from the tree
    sss_addr_t current_addr = sig->address;
    for (int h = 0; h < TREE_HEIGHT; ++h) {
        int bit_idx = h;
        int chunk = bit_idx / 64;
        int bit_in_chunk = bit_idx % 64;

        sss_addr_t sibling_addr = current_addr;
        uint64_t *target_chunk = NULL;

        if (chunk == 0) target_chunk = &sibling_addr.leaf;
        else if (chunk == 1) target_chunk = &sibling_addr.twig;
        else if (chunk - 2 < 2) target_chunk = &sibling_addr.branch[chunk - 2];
        else if (chunk - 4 < 2) target_chunk = &sibling_addr.log[chunk - 4];
        else target_chunk = &sibling_addr.hypertree[chunk - 6];

        // Flip bit to get sibling
        *target_chunk ^= (1ULL << bit_in_chunk);

        if (!compute_node_at_height(master_seed, &sibling_addr, h, sig->auth_path[h])) {
            return false;
        }

        // Clear bit in current_addr to track path upward
        *target_chunk &= ~(1ULL << bit_in_chunk);
    }

    return true;
}

bool sss_verify(const unsigned char *root, const void *message, size_t message_size, const unsigned char *signature_in) {
    if (root == NULL || message == NULL || signature_in == NULL) return false;

    const sss_signature_t *sig = (const sss_signature_t *)signature_in;
    unsigned char msg_hash[HASH_OUT_SIZE];
    sss_sha512(message, message_size, msg_hash);

    wots_public_key pub;
    if (!wots_recover_public(&sig->wots_sig, msg_hash, &pub)) return false;

    unsigned char current_node[HASH_OUT_SIZE];
    if (!domain_hash(DOMAIN_LEAF, &pub, sizeof(pub), NULL, 0, current_node)) {
        memset(&pub, 0, sizeof(pub));
        return false;
    }
    memset(&pub, 0, sizeof(pub));

    for (int h = 0; h < TREE_HEIGHT; ++h) {
        int bit_idx = h;
        int chunk = bit_idx / 64;
        int bit_in_chunk = bit_idx % 64;

        uint64_t leaf_chunk_val = 0;
        if (chunk == 0) leaf_chunk_val = sig->address.leaf;
        else if (chunk == 1) leaf_chunk_val = sig->address.twig;
        else if (chunk - 2 < 2) leaf_chunk_val = sig->address.branch[chunk - 2];
        else if (chunk - 4 < 2) leaf_chunk_val = sig->address.log[chunk - 4];
        else leaf_chunk_val = sig->address.hypertree[chunk - 6];

        bool bit = (leaf_chunk_val >> bit_in_chunk) & 1;

        unsigned char parent_input[HASH_OUT_SIZE * 2];
        if (bit == 0) {
            memcpy(parent_input, current_node, HASH_OUT_SIZE);
            memcpy(parent_input + HASH_OUT_SIZE, sig->auth_path[h], HASH_OUT_SIZE);
        } else {
            memcpy(parent_input, sig->auth_path[h], HASH_OUT_SIZE);
            memcpy(parent_input + HASH_OUT_SIZE, current_node, HASH_OUT_SIZE);
        }

        if (!domain_hash(DOMAIN_NODE, parent_input, sizeof(parent_input), NULL, 0, current_node)) {
            memset(parent_input, 0, sizeof(parent_input));
            return false;
        }
        memset(parent_input, 0, sizeof(parent_input));
    }

    bool success = (memcmp(current_node, root, HASH_OUT_SIZE) == 0);
    memset(current_node, 0, HASH_OUT_SIZE);
    return success;
}