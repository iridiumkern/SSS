#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "sss.h"

#define WOTS_W 16
#define WOTS_LOG_W 4

#define WOTS_LEN1 128
#define WOTS_LEN2 3
#define WOTS_LEN 131

#define TREE_HEIGHT 64
#define HT_LAYERS 8
#define HT_TREE_HEIGHT 8

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
    wots_signature sig;
    unsigned char auth_path[HT_TREE_HEIGHT][HASH_OUT_SIZE];
} hypertree_layer_t;

typedef struct {
    sss_addr_t address;
    wots_signature wots_sig;
    unsigned char auth_path[HT_TREE_HEIGHT][HASH_OUT_SIZE];
    hypertree_layer_t layers[HT_LAYERS - 1];
} sss_signature_t;

static void serialize_address(const sss_addr_t *addr, unsigned char *buf) {
    size_t offset = 0;
    for (int i = 0; i < 2; ++i) {
        uint64_t val = addr->hypertree[i];
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    }
    for (int i = 0; i < 2; ++i) {
        uint64_t val = addr->log[i];
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    }
    for (int i = 0; i < 2; ++i) {
        uint64_t val = addr->branch[i];
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    }
    {
        uint64_t val = addr->twig;
        for (int b = 0; b < 8; ++b) buf[offset++] = (val >> (b * 8)) & 0xFF;
    }
    {
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
    unsigned char input[1 + HASH_OUT_SIZE];
    unsigned char hash[HASH_OUT_SIZE];

    input[0] = DOMAIN_WOTS;
    memcpy(input + 1, value, HASH_OUT_SIZE);

    if (!sss_sha512(input, sizeof(input), hash)) {
        memset(input, 0, sizeof(input));
        memset(hash, 0, sizeof(hash));
        return false;
    }

    memcpy(value, hash, HASH_OUT_SIZE);

    memset(input, 0, sizeof(input));
    memset(hash, 0, sizeof(hash));

    return true;
}

static bool wots_chain(unsigned char *value, size_t steps) {
	while (steps-- != 0) {
		if (!wots_hash(value)) {
			memset(value, 0, HASH_OUT_SIZE);
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
    wots_public_key pub;
    unsigned char serialized_addr[64];
    unsigned char combined_input[64 + 4];
    unsigned char value[HASH_OUT_SIZE];

    if (master_seed == NULL || address == NULL || leaf == NULL) return false;

    serialize_address(address, serialized_addr);
    memcpy(combined_input, serialized_addr, 64);

    for (size_t i = 0; i < WOTS_LEN; ++i) {
        uint32_t idx = (uint32_t)i;

        combined_input[64] = idx & 0xFF;
        combined_input[65] = (idx >> 8) & 0xFF;
        combined_input[66] = (idx >> 16) & 0xFF;
        combined_input[67] = (idx >> 24) & 0xFF;

        if (!domain_hash(DOMAIN_PRIVATE, master_seed, HASH_OUT_SIZE, combined_input, sizeof(combined_input), value)) {
            memset(&pub, 0, sizeof(pub));
            memset(value, 0, sizeof(value));
            memset(combined_input, 0, sizeof(combined_input));
            memset(serialized_addr, 0, sizeof(serialized_addr));
            return false;
        }

        for (size_t step = 0; step < WOTS_W - 1; ++step) {
            if (!wots_hash(value)) {
                memset(&pub, 0, sizeof(pub));
                memset(value, 0, sizeof(value));
                memset(combined_input, 0, sizeof(combined_input));
                memset(serialized_addr, 0, sizeof(serialized_addr));
                return false;
            }
        }

        memcpy(pub.element[i], value, HASH_OUT_SIZE);
    }

    bool res = domain_hash(DOMAIN_LEAF, &pub, sizeof(pub), NULL, 0, leaf);

    memset(&pub, 0, sizeof(pub));
    memset(value, 0, sizeof(value));
    memset(combined_input, 0, sizeof(combined_input));
    memset(serialized_addr, 0, sizeof(serialized_addr));

    return res;
}

static void sss_set_layer(sss_addr_t *addr, int layer) {
    addr->hypertree[0] = (uint64_t)layer;
}

static bool compute_subtree(const unsigned char *master_seed, const sss_addr_t *base_address, int height, unsigned char *root_out, unsigned char auth_path_out[][HASH_OUT_SIZE], uint64_t leaf_idx) {
    if (!master_seed || !base_address || !root_out) return false;
    if (height < 0 || height > 64) return false;
    if (height >= (int)(sizeof(size_t) * 8 - 1)) return false;

    size_t leaf_count = (size_t)1 << height;

    if (leaf_idx >= leaf_count) return false;
    if (leaf_count > SIZE_MAX / HASH_OUT_SIZE) return false;

    unsigned char *nodes = malloc(leaf_count * HASH_OUT_SIZE);
    unsigned char *next = malloc((leaf_count / 2) * HASH_OUT_SIZE);

    if (!nodes || !next) {
        free(nodes);
        free(next);
        return false;
    }

    for (size_t i = 0; i < leaf_count; ++i) {
        sss_addr_t addr = *base_address;
        addr.leaf = (addr.leaf & ~((UINT64_C(1) << height) - 1)) | i;

        if (!sss_leaf_from_address(master_seed, &addr, nodes + i * HASH_OUT_SIZE)) {
            free(nodes);
            free(next);
            return false;
        }
    }

    size_t count = leaf_count;
    size_t index = leaf_idx;

    for (int h = 0; h < height; ++h) {
        if (auth_path_out) {
            size_t sibling = index ^ 1;

            memcpy(auth_path_out[h], nodes + sibling * HASH_OUT_SIZE, HASH_OUT_SIZE);
        }

        for (size_t i = 0; i < count / 2; ++i) {
            if (!sss_hash_node(nodes + (i * 2) * HASH_OUT_SIZE, nodes + (i * 2 + 1) * HASH_OUT_SIZE, next + i * HASH_OUT_SIZE)) {
                free(nodes);
                free(next);
                return false;
            }
        }

        memcpy(nodes, next, (count / 2) * HASH_OUT_SIZE);

        index >>= 1;
        count >>= 1;
    }

    memcpy(root_out, nodes, HASH_OUT_SIZE);

    memset(nodes, 0, leaf_count * HASH_OUT_SIZE);
    memset(next, 0, (leaf_count / 2) * HASH_OUT_SIZE);

    free(nodes);
    free(next);

    return true;
}

bool sss_generate_keypair(unsigned char *master_seed, unsigned char *root) {
    if (!master_seed || !root || !sss_get512randsecure(master_seed)) return false;

    sss_addr_t addr;
    memset(&addr, 0, sizeof(addr));

    sss_set_layer(&addr, HT_LAYERS - 1);

    if (!compute_subtree(master_seed, &addr, HT_TREE_HEIGHT, root, NULL, 0)) {
        memset(root, 0, HASH_OUT_SIZE);
        return false;
    }

    return true;
}

bool sss_sign(const unsigned char *master_seed, const void *message, size_t message_size, unsigned char *signature_out) {
    if (!master_seed || !message || !signature_out) return false;

    sss_signature_t *sig = (sss_signature_t *)signature_out;
    unsigned char msg_hash[HASH_OUT_SIZE];
    unsigned char current_input[HASH_OUT_SIZE];
    sss_addr_t addr;

    if (!sss_sha512(message, message_size, msg_hash)) return false;

    uint64_t total_idx = 0;
    memcpy(&total_idx, msg_hash, sizeof(total_idx));
    memcpy(current_input, msg_hash, HASH_OUT_SIZE);

    memset(&addr, 0, sizeof(addr));
    memset(sig, 0, sizeof(*sig));

    for (int layer = 0; layer < HT_LAYERS; ++layer) {
        uint64_t leaf_idx;
        wots_private_key priv;
        wots_signature *wots_sig;
        unsigned char (*auth_path)[HASH_OUT_SIZE];

        sss_set_layer(&addr, layer);

        leaf_idx = (total_idx >> (layer * HT_TREE_HEIGHT)) & ((UINT64_C(1) << HT_TREE_HEIGHT) - 1);

        addr.leaf = leaf_idx;

        if (!sss_ots_generate_private(master_seed, &addr, &priv)) {
            memset(&priv, 0, sizeof(priv));
            return false;
        }

        if (layer == 0) {
            sig->address = addr;
            wots_sig = &sig->wots_sig;
            auth_path = sig->auth_path;
        } else {
            hypertree_layer_t *Layer = &sig->layers[layer - 1];
            wots_sig = &Layer->sig;
            auth_path = Layer->auth_path;
        }

        if (!wots_sign(&priv, current_input, wots_sig)) {
            memset(&priv, 0, sizeof(priv));
            return false;
        }

        if (!compute_subtree(master_seed, &addr, HT_TREE_HEIGHT, current_input, auth_path, leaf_idx)) {
            memset(&priv, 0, sizeof(priv));
            return false;
        }

        memset(&priv, 0, sizeof(priv));
    }

    return true;
}

bool sss_verify(const unsigned char *root, const void *message, size_t message_size, const unsigned char *signature_in) {
    if (!root || !message || !signature_in) return false;

    const sss_signature_t *sig = (const sss_signature_t *)signature_in;
    unsigned char msg_hash[HASH_OUT_SIZE];
    sss_addr_t addr;

    if (!sss_sha512(message, message_size, msg_hash)) return false;

    uint64_t total_idx = 0;
    memcpy(&total_idx, msg_hash, sizeof(total_idx));

    memset(&addr, 0, sizeof(addr));
    sss_set_layer(&addr, 0);
    addr.leaf = total_idx & ((UINT64_C(1) << HT_TREE_HEIGHT) - 1);

    if (memcmp(&sig->address, &addr, sizeof(addr)) != 0) return false;

    unsigned char current_node[HASH_OUT_SIZE];
    wots_public_key pub;

    if (!wots_recover_public(&sig->wots_sig, msg_hash, &pub)) return false;
    if (!domain_hash(DOMAIN_LEAF, &pub, sizeof(pub), NULL, 0, current_node)) return false;

    for (int h = 0; h < HT_TREE_HEIGHT; ++h) {
        bool bit = (addr.leaf >> h) & 1;
        unsigned char parent_input[HASH_OUT_SIZE * 2];

        if (!bit) {
            memcpy(parent_input, current_node, HASH_OUT_SIZE);
            memcpy(parent_input + HASH_OUT_SIZE, sig->auth_path[h], HASH_OUT_SIZE);
        } else {
            memcpy(parent_input, sig->auth_path[h], HASH_OUT_SIZE);
            memcpy(parent_input + HASH_OUT_SIZE, current_node, HASH_OUT_SIZE);
        }

        if (!domain_hash(DOMAIN_NODE, parent_input, sizeof(parent_input), NULL, 0, current_node))
            return false;
    }

    for (int layer = 1; layer < HT_LAYERS; ++layer) {
        const hypertree_layer_t *Layer = &sig->layers[layer - 1];

        uint64_t leaf_idx = (total_idx >> (layer * HT_TREE_HEIGHT)) & ((UINT64_C(1) << HT_TREE_HEIGHT) - 1);

        if (!wots_recover_public(&Layer->sig, current_node, &pub)) return false;
        if (!domain_hash(DOMAIN_LEAF, &pub, sizeof(pub), NULL, 0, current_node)) return false;

        for (int h = 0; h < HT_TREE_HEIGHT; ++h) {
            bool bit = (leaf_idx >> h) & 1;
            unsigned char parent_input[HASH_OUT_SIZE * 2];
            const unsigned char *auth_node = Layer->auth_path[h];

            if (!bit) {
                memcpy(parent_input, current_node, HASH_OUT_SIZE);
                memcpy(parent_input + HASH_OUT_SIZE, auth_node, HASH_OUT_SIZE);
            } else {
                memcpy(parent_input, auth_node, HASH_OUT_SIZE);
                memcpy(parent_input + HASH_OUT_SIZE, current_node, HASH_OUT_SIZE);
            }

            if (!domain_hash(DOMAIN_NODE, parent_input, sizeof(parent_input), NULL, 0, current_node))
                return false;
        }
    }

    return memcmp(current_node, root, HASH_OUT_SIZE) == 0;
}

#ifndef SSS_DEBUG
// Only use this when actually debugging, uses printf!
#include <stdio.h>

void sss_debug_test(void) {
    unsigned char master_seed[HASH_OUT_SIZE];
    unsigned char root[HASH_OUT_SIZE];

    printf("[DEBUG] Starting sss_debug_test...\n");

    printf("[DEBUG] Testing keypair generation...\n");
    if (!sss_generate_keypair(master_seed, root)) {
        printf("[DEBUG] FAIL: sss_generate_keypair returned false.\n");
        return;
    }
    printf("[DEBUG] PASS: Keypair generated successfully.\n");

    const char *message = "Hello, SSS Cryptosystem!";
    size_t message_size = strlen(message);

    unsigned char signature_buf[sizeof(sss_signature_t)];
    memset(signature_buf, 0, sizeof(signature_buf));

    printf("[DEBUG] Testing signing process...\n");
    if (!sss_sign(master_seed, message, message_size, signature_buf)) {
        printf("[DEBUG] FAIL: sss_sign returned false.\n");
        return;
    }
    printf("[DEBUG] PASS: Message signed successfully.\n");

    printf("[DEBUG] Testing signature verification (valid message/sig)...\n");
    if (!sss_verify(root, message, message_size, signature_buf)) {
        printf("[DEBUG] FAIL: sss_verify failed on valid signature.\n");
        return;
    }
    printf("[DEBUG] PASS: Signature verified successfully.\n");

    printf("[DEBUG] Testing signature verification (tampered message)...\n");
    const char *bad_message = "Tampered Message!";
    if (sss_verify(root, bad_message, strlen(bad_message), signature_buf)) {
        printf("[DEBUG] FAIL: sss_verify accepted a tampered message!\n");
        return;
    }
    printf("[DEBUG] PASS: Tampered message correctly rejected.\n");

    printf("[DEBUG] All debug tests completed successfully.\n");
}
#endif