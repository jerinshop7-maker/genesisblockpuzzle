/* Fast BIP39/BIP32/BIP48 escrow search engine.
 *
 * Correctness contract: this engine must agree with evidence/reference.py,
 * which is pinned to BitcoinJS xpubs and the official BIP39 vectors.
 *
 * Structure of the search (from the author's own OP_RETURN answers):
 *   entropy = SHA256(digest_input)[0:16]          (confirmed, block 968343)
 *   words   = BIP39(entropy)  -> 12 words          (confirmed)
 *   seed    = PBKDF2-HMAC-SHA512(words, "mnemonic" + passphrase)
 *   keys    = m/48'/0'/ACCOUNT'/SCRIPT'/<leaf pair>   ("multisig/mainnet/genesis_data/script_type")
 *   script  = OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
 *   require SHA256(script) == escrow witness program
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static const char *TARGET_HEX = "4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833";
static unsigned char TARGET[32];

/* EC_GROUP is read-only after setup and safe to share. BN_CTX and BIGNUM
 * scratch space are NOT thread-safe, so every worker allocates its own. */
static EC_GROUP *GRP;
static const EVP_MD *SHA512_MD;

static const char *WORDLIST[2048];

/* ------------------------------------------------------------------ helpers */
static void die(const char *m) { fprintf(stderr, "fatal: %s\n", m); exit(2); }

static void sha256(const unsigned char *d, size_t n, unsigned char *out) {
    unsigned int len = 32;
    EVP_Digest(d, n, out, &len, EVP_sha256(), NULL);
}

static void load_wordlist(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) die("cannot open wordlist");
    char line[64];
    int i = 0;
    while (i < 2048 && fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        WORDLIST[i++] = strdup(line);
    }
    fclose(f);
    if (i != 2048) die("wordlist must have 2048 entries");
}

/* BIP39: 16-byte entropy -> 12 words */
static void entropy_to_mnemonic(const unsigned char *ent, char out[256]) {
    unsigned char h[32];
    sha256(ent, 16, h);
    unsigned char bits[17];
    memcpy(bits, ent, 16);
    bits[16] = h[0];            /* 4 checksum bits = top nibble of sha256 */
    int pos = 0;
    out[0] = 0;   /* strcat below needs a terminated, empty string */
    for (int i = 0; i < 12; i++) {
        unsigned idx = 0;
        for (int b = 0; b < 11; b++) {
            int p = pos + b;
            idx = (idx << 1) | ((bits[p >> 3] >> (7 - (p & 7))) & 1);
        }
        pos += 11;
        if (i) strcat(out, " ");
        strcat(out, WORDLIST[idx]);
    }
}

static void pbkdf2_seed(const char *mn, const char *pass, unsigned char out[64]) {
    char salt[512];
    snprintf(salt, sizeof(salt), "mnemonic%s", pass);
    PKCS5_PBKDF2_HMAC(mn, (int)strlen(mn), (unsigned char *)salt, (int)strlen(salt),
                      2048, SHA512_MD, 64, out);
}

/* ------------------------------------------------------------------ BIP32 */
typedef struct { BIGNUM *k; unsigned char c[32]; } Node;

static void hex_print(const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

/* BN_CTX is per-thread; EC_GROUP is read-only after setup and shared. */
static __thread BN_CTX *g_ctx;
static __thread BIGNUM *t_order;

static void ser_pub33(const BIGNUM *priv, unsigned char out[33]) {
    EC_POINT *pt = EC_POINT_new(GRP);
    EC_POINT_mul(GRP, pt, priv, NULL, NULL, g_ctx);
    size_t len = 33;
    EC_POINT_point2oct(GRP, pt, POINT_CONVERSION_COMPRESSED, out, len, g_ctx);
    EC_POINT_free(pt);
}

static void node_master(Node *n, const unsigned char seed[64]) {
    unsigned char I[64];
    unsigned int l = 64;
    HMAC(SHA512_MD, "Bitcoin seed", 12, seed, 64, I, &l);
    n->k = BN_bin2bn(I, 32, NULL);
    memcpy(n->c, I + 32, 32);
}

static void node_free(Node *n) { if (n->k) BN_free(n->k); n->k = NULL; }

static int node_ckd(const Node *par, uint32_t index, Node *out) {
    unsigned char data[80], I[64];
    unsigned int l = 64;
    if (index & 0x80000000u) {
        data[0] = 0;
        BN_bn2binpad(par->k, data + 1, 32);
        data[33] = (index >> 24) & 0xff; data[34] = (index >> 16) & 0xff;
        data[35] = (index >> 8) & 0xff;  data[36] = index & 0xff;
        HMAC(SHA512_MD, par->c, 32, data, 37, I, &l);
    } else {
        ser_pub33(par->k, data);
        data[33] = (index >> 24) & 0xff; data[34] = (index >> 16) & 0xff;
        data[35] = (index >> 8) & 0xff;  data[36] = index & 0xff;
        HMAC(SHA512_MD, par->c, 32, data, 37, I, &l);
    }
    BIGNUM *IL = BN_bin2bn(I, 32, NULL);
    if (BN_cmp(IL, t_order) >= 0) { BN_free(IL); return 0; }
    out->k = BN_new();
    BN_mod_add(out->k, IL, par->k, t_order, g_ctx);
    memcpy(out->c, I + 32, 32);
    int bad = BN_is_zero(out->k);
    BN_free(IL);
    return !bad;
}

static int node_path(const Node *root, const uint32_t *path, int n, Node *out) {
    Node cur = *root;
    for (int i = 0; i < n; i++) {
        Node nx;
        if (!node_ckd(&cur, path[i], &nx)) {
            if (i) node_free(&cur);
            return 0;
        }
        if (i) node_free(&cur);
        cur = nx;
    }
    *out = cur;
    return 1;
}

/* ------------------------------------------------------------------ config */
typedef struct {
    char digest_input[4096];
    int  digest_input_len;
    char label[256];
} DigestCase;

typedef struct {
    char passphrase[128];
} PassCase;

typedef struct {
    uint32_t account;
    char label[64];
} AccountCase;

#define MAX_LEAF 64

/* A distinct leaf path, derived once per account and cached as a pubkey. */
typedef struct {
    uint32_t leaf[4];
    int      n;
} LeafPath;

/* A pair of cached leaf indices. */
typedef struct {
    int  ua, ub;
    char label[64];
} LeafCase;

static LeafPath  UNIQUE_LEAF[MAX_LEAF];
static int       N_UNIQUE_LEAF;
static LeafCase  *LEAVES;  static int N_LEAF;

static DigestCase  *DIGESTS;  static int N_DIGEST;
static PassCase    *PASSES;   static int N_PASS;
static AccountCase *ACCOUNTS; static int N_ACCT;


/* All cases are parsed on the main thread before any worker starts, and the
 * arrays are only ever grown during parsing. Workers only read. */
static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) die("out of memory");
    return q;
}

static volatile int FOUND = 0;
static int MODE_INDEP = 0;   /* 1 = two independent BIP48 roots (one per cosigner) */
static pthread_mutex_t PRINT_LOCK = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int id, nthreads;
    long long checked;
} WorkerArg;

static int check_pair(const unsigned char *p1, const unsigned char *p2) {
    unsigned char script[71];
    script[0] = 0x52;                 /* OP_2 */
    script[1] = 33; memcpy(script + 2, p1, 33);
    script[35] = 33; memcpy(script + 36, p2, 33);
    script[69] = 0x52;                /* OP_2 */
    script[70] = 0xae;                /* OP_CHECKMULTISIG */
    unsigned char h[32];
    sha256(script, 71, h);
    return memcmp(h, TARGET, 32) == 0;
}

static void report_match(const DigestCase *d, const unsigned char *ent,
                         const char *words, const char *pass_a, const char *pass_b,
                         const AccountCase *acct, const char *leaflab,
                         const unsigned char *k1, const unsigned char *k2) {
    pthread_mutex_lock(&PRINT_LOCK);
    if (!FOUND) {
        FOUND = 1;
        printf("MATCH\n");
        printf("  digest   : %s\n", d->label);
        printf("  inputhex : ");
        for (int i = 0; i < d->digest_input_len; i++)
            printf("%02x", (unsigned char)d->digest_input[i]);
        printf("\n  inputtxt : ");
        for (int i = 0; i < d->digest_input_len; i++) {
            unsigned char ch = (unsigned char)d->digest_input[i];
            putchar(ch >= 32 && ch < 127 ? ch : '.');
        }
        printf("\n  entropy  : "); hex_print(ent, 16);
        printf("\n  words    : %s\n", words);
        printf("  pass_a   : %s\n", pass_a);
        printf("  pass_b   : %s\n", pass_b);
        printf("  account  : %u (%s)\n", acct->account, acct->label);
        printf("  leaves   : %s\n", leaflab);
        printf("  key_a    : "); hex_print(k1, 33);
        printf("\n  key_b    : "); hex_print(k2, 33);
        printf("\n");
        fflush(stdout);
    }
    pthread_mutex_unlock(&PRINT_LOCK);
}

/* Derive m/48'/0'/ACCOUNT'/2'/leaf for one BIP48 root and return its pubkey. */
static int bip48_pub(const unsigned char seed[64], uint32_t account,
                     const uint32_t *leaf, int nleaf, unsigned char out[33]) {
    Node root, base, acct, lf;
    node_master(&root, seed);
    uint32_t prefix[2] = {0x80000030u, 0x80000000u};
    int ok = node_path(&root, prefix, 2, &base);
    if (ok) {
        uint32_t tail[2] = {0x80000000u | account, 0x80000002u};
        ok = node_path(&base, tail, 2, &acct);
        if (ok) {
            uint32_t lp[4];
            for (int i = 0; i < nleaf; i++) lp[i] = leaf[i] | 0x80000000u;
            ok = node_path(&acct, lp, nleaf, &lf);
            if (ok) { ser_pub33(lf.k, out); node_free(&lf); }
        }
        node_free(&acct);
        node_free(&base);
    }
    node_free(&root);
    return ok;
}

static void *worker(void *arg) {
    WorkerArg *wa = arg;
    g_ctx = BN_CTX_new();
    t_order = BN_new();
    EC_GROUP_get_order(GRP, t_order, g_ctx);
    Node root;
    root.k = NULL;
    for (int di = wa->id; di < N_DIGEST && !FOUND; di += wa->nthreads) {
        unsigned char ent[16];
        sha256((unsigned char *)DIGESTS[di].digest_input,
               (size_t)DIGESTS[di].digest_input_len, ent);
        char words[256];
        entropy_to_mnemonic(ent, words);

        for (int pi = 0; pi < N_PASS && !FOUND; pi++) {
            unsigned char seed[64];
            pbkdf2_seed(words, PASSES[pi].passphrase, seed);
            if (root.k) node_free(&root);
            node_master(&root, seed);

            /* m/48'/0' is the same for every account, so derive it once and
             * only walk the account and script-type levels per candidate. */
            uint32_t prefix[2] = {0x80000030u, 0x80000000u};
            Node base;
            if (!node_path(&root, prefix, 2, &base)) continue;

            for (int ai = 0; ai < N_ACCT && !FOUND; ai++) {
                uint32_t path[2] = {0x80000000u | ACCOUNTS[ai].account, 0x80000002u};
                Node acct;
                if (!node_path(&base, path, 2, &acct)) continue;

                /* Derive every distinct leaf node for this account once, and
                 * cache its compressed pubkey. Leaf pairs are then pure
                 * comparisons, so adding pair layouts costs nothing. */
                unsigned char (*pk)[33] = calloc(MAX_LEAF, 33);
                int *have = calloc(MAX_LEAF, sizeof(int));
                if (!pk || !have) die("oom");
                for (int u = 0; u < N_UNIQUE_LEAF; u++) {
                    uint32_t lp[4];
                    int ln = UNIQUE_LEAF[u].n;
                    for (int j = 0; j < ln; j++) lp[j] = UNIQUE_LEAF[u].leaf[j] | 0x80000000u;
                    Node ln_node;
                    if (node_path(&acct, lp, ln, &ln_node)) {
                        ser_pub33(ln_node.k, pk[u]);
                        have[u] = 1;
                        node_free(&ln_node);
                    }
                }

                for (int li = 0; li < N_LEAF && !FOUND; li++) {
                    if (!have[LEAVES[li].ua] || !have[LEAVES[li].ub]) continue;
                    unsigned char k1[33], k2[33];
                    memcpy(k1, pk[LEAVES[li].ua], 33);
                    memcpy(k2, pk[LEAVES[li].ub], 33);
                    wa->checked++;
                    int hit = check_pair(k1, k2);
                    if (!hit) {
                        unsigned char a[33], b[33];
                        memcpy(a, k1, 33); memcpy(b, k2, 33);
                        if (a[0] > b[0] || (a[0] == b[0] && memcmp(a, b, 33) > 0)) {
                            unsigned char t[33]; memcpy(t, a, 33);
                            memcpy(a, b, 33); memcpy(b, t, 33);
                        }
                        hit = check_pair(a, b);
                    }
                    if (hit) {
                        pthread_mutex_lock(&PRINT_LOCK);
                        if (!FOUND) {
                            FOUND = 1;
                            printf("MATCH\n");
                            printf("  digest   : %s\n", DIGESTS[di].label);
                            printf("  inputhex : ");
                            for (int i = 0; i < DIGESTS[di].digest_input_len; i++)
                                printf("%02x", (unsigned char)DIGESTS[di].digest_input[i]);
                            printf("\n  inputtxt : ");
                            for (int i = 0; i < DIGESTS[di].digest_input_len; i++) {
                                unsigned char ch = (unsigned char)DIGESTS[di].digest_input[i];
                                putchar(ch >= 32 && ch < 127 ? ch : '.');
                            }
                            printf("\n");
                            printf("  entropy  : "); hex_print(ent, 16);
                            printf("\n  words    : %s\n", words);
                            printf("  pass     : %s\n", PASSES[pi].passphrase);
                            printf("  account  : %u (%s)\n", ACCOUNTS[ai].account, ACCOUNTS[ai].label);
                            printf("  leaves   : %s\n", LEAVES[li].label);
                            printf("  key1     : "); hex_print(k1, 33);
                            printf("\n  key2     : "); hex_print(k2, 33);
                            printf("\n");
                            fflush(stdout);
                        }
                        pthread_mutex_unlock(&PRINT_LOCK);
                    }
                }
                free(pk); free(have);
                node_free(&acct);
            }
            node_free(&base);
        }
    }
    if (root.k) node_free(&root);
    BN_free(t_order);
    BN_CTX_free(g_ctx);
    return NULL;
}

/* ------------------------------------------------------------------ mode 2
 *
 * Independent-root model: a real 2-of-2 multisig has one seed per cosigner,
 * and both are used at the SAME path m/48'/0'/ACCOUNT'/2'/leaf. The two keys
 * therefore come from two different BIP39 seeds. The author only said the
 * passphrase "is a name", so both passphrases are drawn from the same name
 * set (which also covers "same name, two different formats").
 *
 * Seeds are cached per (digest, passphrase) and reused across accounts, so the
 * extra cost over the same-root model is one BIP32 walk per distinct seed.
 */
static void *worker_indep(void *arg) {
    WorkerArg *wa = arg;
    g_ctx = BN_CTX_new();
    t_order = BN_new();
    EC_GROUP_get_order(GRP, t_order, g_ctx);

    size_t nslot = (size_t)N_PASS * (size_t)N_UNIQUE_LEAF;
    if (nslot == 0) nslot = 1;
    unsigned char (*pk)[33] = calloc(nslot, 33);
    int *have = calloc(nslot, sizeof(int));
    if (!pk || !have) die("oom");
#define SLOT(pi, u) ((size_t)(pi) * (size_t)N_UNIQUE_LEAF + (size_t)(u))

    for (int di = wa->id; di < N_DIGEST && !FOUND; di += wa->nthreads) {
        unsigned char ent[16];
        sha256((unsigned char *)DIGESTS[di].digest_input,
               (size_t)DIGESTS[di].digest_input_len, ent);
        char words[256];
        entropy_to_mnemonic(ent, words);

        for (int ai = 0; ai < N_ACCT && !FOUND; ai++) {
            memset(have, 0, nslot * sizeof(int));
            /* Derive every (passphrase, leaf) pubkey once for this account. */
            for (int pi = 0; pi < N_PASS; pi++) {
                unsigned char seed[64];
                pbkdf2_seed(words, PASSES[pi].passphrase, seed);
                for (int u = 0; u < N_UNIQUE_LEAF; u++) {
                    if (have[SLOT(pi, u)]) continue;
                    if (bip48_pub(seed, ACCOUNTS[ai].account, UNIQUE_LEAF[u].leaf,
                                  UNIQUE_LEAF[u].n, pk[SLOT(pi, u)]))
                        have[SLOT(pi, u)] = 1;
                }
            }
            for (int li = 0; li < N_LEAF && !FOUND; li++) {
                int ua = LEAVES[li].ua, ub = LEAVES[li].ub;
                for (int pa = 0; pa < N_PASS && !FOUND; pa++) {
                    if (!have[SLOT(pa, ua)]) continue;
                    for (int pb = pa + 1; pb < N_PASS; pb++) {
                        if (!have[SLOT(pb, ub)]) continue;
                        const unsigned char *k1 = pk[SLOT(pa, ua)];
                        const unsigned char *k2 = pk[SLOT(pb, ub)];
                        if (memcmp(k1, k2, 33) == 0) continue;   /* same key, not 2-of-2 */
                        wa->checked++;
                        if (check_pair(k1, k2)) {
                            report_match(&DIGESTS[di], ent, words,
                                         PASSES[pa].passphrase, PASSES[pb].passphrase,
                                         &ACCOUNTS[ai], LEAVES[li].label, k1, k2);
                            break;
                        }
                        unsigned char a[33], b[33];
                        memcpy(a, k1, 33); memcpy(b, k2, 33);
                        if (a[0] > b[0] || (a[0] == b[0] && memcmp(a, b, 33) > 0)) {
                            unsigned char t[33]; memcpy(t, a, 33);
                            memcpy(a, b, 33); memcpy(b, t, 33);
                        }
                        if (check_pair(a, b)) {
                            report_match(&DIGESTS[di], ent, words,
                                         PASSES[pa].passphrase, PASSES[pb].passphrase,
                                         &ACCOUNTS[ai], LEAVES[li].label, k1, k2);
                            break;
                        }
                    }
                }
            }
        }
    }
    free(pk); free(have);
#undef SLOT
    BN_free(t_order);
    BN_CTX_free(g_ctx);
    return NULL;
}

int main(int argc, char **argv) {
    SHA512_MD = EVP_sha512();
    GRP = EC_GROUP_new_by_curve_name(NID_secp256k1);
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(TARGET_HEX + 2 * i, "%2x", &v); TARGET[i] = (unsigned char)v;
    }
    load_wordlist("english.txt");

    /* Loaded from stdin by the Python driver:
     * D <intlen> <label>\n<input bytes>\n P <pass>\n A <acct> <label>\n L <label> <na> <a...> <nb> <b...> */
    char line[8192];
    int cap_d = 0, cap_p = 0, cap_a = 0, cap_l = 0;
    while (fgets(line, sizeof(line), stdin)) {
        char kind = line[0];
        if (kind == 'D') {
            int n; char label[256];
            if (sscanf(line + 2, "%d %255[^\n]", &n, label) != 2) die("bad D line");
            if (N_DIGEST == cap_d) {
                cap_d = cap_d ? cap_d * 2 : 64;
                DIGESTS = xrealloc(DIGESTS, cap_d * sizeof(DigestCase));
                memset(DIGESTS + (cap_d / 2), 0, (cap_d / 2) * sizeof(DigestCase));
            }
            /* Payload is hex so the whole protocol stays line-oriented. */
            char *hex = malloc((size_t)n * 2 + 1);
            for (int i = 0; i < n * 2; i++) {
                int c = fgetc(stdin);
                if (c == EOF) die("short D payload");
                hex[i] = (char)c;
            }
            hex[n * 2] = 0;
            fgetc(stdin); /* trailing newline */
            if ((int)strlen(hex) != n * 2) die("bad D hex length");
            for (int i = 0; i < n; i++) {
                unsigned v; sscanf(hex + 2 * i, "%2x", &v);
                DIGESTS[N_DIGEST].digest_input[i] = (char)v;
            }
            DIGESTS[N_DIGEST].digest_input[n] = 0;
            DIGESTS[N_DIGEST].digest_input_len = n;
            snprintf(DIGESTS[N_DIGEST].label, sizeof(DIGESTS[N_DIGEST].label), "%s", label);
            N_DIGEST++;
            free(hex);
        } else if (kind == 'P') {
            if (N_PASS == cap_p) {
                cap_p = cap_p ? cap_p * 2 : 32;
                PASSES = xrealloc(PASSES, cap_p * sizeof(PassCase));
                memset(PASSES + (cap_p / 2), 0, (cap_p / 2) * sizeof(PassCase));
            }
            snprintf(PASSES[N_PASS].passphrase, sizeof(PASSES[N_PASS].passphrase), "%s", line + 2);
            char *nl = strchr(PASSES[N_PASS].passphrase, '\n');
            if (nl) *nl = 0;
            N_PASS++;
        } else if (kind == 'A') {
            if (N_ACCT == cap_a) {
                cap_a = cap_a ? cap_a * 2 : 32;
                ACCOUNTS = xrealloc(ACCOUNTS, cap_a * sizeof(AccountCase));
                memset(ACCOUNTS + (cap_a / 2), 0, (cap_a / 2) * sizeof(AccountCase));
            }
            unsigned v; char label[64];
            if (sscanf(line + 2, "%u %63[^\n]", &v, label) != 2) die("bad A line");
            ACCOUNTS[N_ACCT].account = v;
            snprintf(ACCOUNTS[N_ACCT].label, 64, "%s", label);
            N_ACCT++;
        } else if (kind == 'L') {
            if (N_LEAF == cap_l) {
                cap_l = cap_l ? cap_l * 2 : 16;
                LEAVES = xrealloc(LEAVES, cap_l * sizeof(LeafCase));
                memset(LEAVES + (cap_l / 2), 0, (cap_l / 2) * sizeof(LeafCase));
            }
            char label[64]; int na, nb;
            char *p = line + 2;
            int consumed = 0;
            if (sscanf(p, "%63s %n", label, &consumed) != 1) die("bad L line");
            p += consumed;
            if (sscanf(p, "%d %n", &na, &consumed) != 1 || na > 4) die("bad L na");
            p += consumed;
            uint32_t tmp[4];
            for (int i = 0; i < na; i++) { unsigned v; sscanf(p, "%u %n", &v, &consumed); tmp[i] = v; p += consumed; }
            if (sscanf(p, "%d %n", &nb, &consumed) != 1 || nb > 4) die("bad L nb");
            p += consumed;
            uint32_t tmp2[4];
            for (int i = 0; i < nb; i++) { unsigned v; sscanf(p, "%u %n", &v, &consumed); tmp2[i] = v; p += consumed; }
            /* Register both sides in the unique-leaf table and remember the
             * indices, so each distinct path is derived only once per account. */
            int ua = -1, ub = -1;
            for (int u = 0; u < N_UNIQUE_LEAF; u++) {
                if (UNIQUE_LEAF[u].n != na) continue;
                if (memcmp(UNIQUE_LEAF[u].leaf, tmp, sizeof(uint32_t) * na) == 0) { ua = u; break; }
            }
            if (ua < 0) {
                if (N_UNIQUE_LEAF >= MAX_LEAF) die("too many unique leaf paths");
                ua = N_UNIQUE_LEAF++;
                UNIQUE_LEAF[ua].n = na;
                memcpy(UNIQUE_LEAF[ua].leaf, tmp, sizeof(uint32_t) * na);
            }
            for (int u = 0; u < N_UNIQUE_LEAF; u++) {
                if (UNIQUE_LEAF[u].n != nb) continue;
                if (memcmp(UNIQUE_LEAF[u].leaf, tmp2, sizeof(uint32_t) * nb) == 0) { ub = u; break; }
            }
            if (ub < 0) {
                if (N_UNIQUE_LEAF >= MAX_LEAF) die("too many unique leaf paths");
                ub = N_UNIQUE_LEAF++;
                UNIQUE_LEAF[ub].n = nb;
                memcpy(UNIQUE_LEAF[ub].leaf, tmp2, sizeof(uint32_t) * nb);
            }
            LEAVES[N_LEAF].ua = ua;
            LEAVES[N_LEAF].ub = ub;
            snprintf(LEAVES[N_LEAF].label, 64, "%s", label);
            N_LEAF++;
        } else if (kind == 'Q') {
            break;
        }
    }
    fprintf(stderr, "engine: digests=%d passes=%d accounts=%d leaves=%d\n",
            N_DIGEST, N_PASS, N_ACCT, N_LEAF);
    fprintf(stderr, "engine: unique leaf paths=%d\n", N_UNIQUE_LEAF);

    int nthreads = 2;
    if (getenv("ENGINE_INDEP")) MODE_INDEP = 1;
    pthread_t th[16];
    WorkerArg wa[16];
    void *(*fn)(void *) = MODE_INDEP ? worker_indep : worker;
    for (int i = 0; i < nthreads; i++) {
        wa[i].id = i; wa[i].nthreads = nthreads; wa[i].checked = 0;
        pthread_create(&th[i], NULL, fn, &wa[i]);
    }
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    long long total = 0;
    for (int i = 0; i < nthreads; i++) total += wa[i].checked;
    if (!FOUND) printf("NO_MATCH checked=%lld\n", total);
    return FOUND ? 0 : 1;
}
