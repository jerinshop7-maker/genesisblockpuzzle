/* engine3: same-passphrase independent-root cross-digest search.
 *
 * Model fixed by the author's OP_RETURNs (blocks 969361/969390/719623a4):
 *   digest_i = cut -b N-M of the raw-block hex text (UTF-8, no newline)
 *   entropy  = SHA256(digest_i)[0:16]          (Ian "Hex" entropy type)
 *   words    = BIP39 English, 12 words
 *   seed     = PBKDF2-HMAC-SHA512(words, "mnemonic" + passphrase)
 *   key_i    = m/48'/0'/ACCOUNT'/2'/leaf   (same passphrase, same account)
 *   script   = OP_2 <key_i> <key_j> OP_2 OP_CHECKMULTISIG
 *   accept iff SHA256(script) == escrow witness program
 *
 * Two cosigners => digest_i and digest_j are (usually different) substrings
 * of the same tool-printed hex, both of the SAME length L in {18..32, even}.
 * i==j with distinct leaf paths covers the same-root two-leaf layout.
 *
 * Protocol on stdin (same line-oriented shape as engine.c):
 *   D <nbytes> <label>\n<2*nbytes hex>\n
 *   P <passphrase>\n
 *   A <account> <label>\n
 *   L <label> <na> <a...> <nb> <b...> [hard]\n
 *   Q\n
 *
 * Mode flag via env:
 *   ENGINE3_ALLLEN=1  pair substrings of ANY lengths (default: same length)
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
#include <time.h>

static const char *TARGET_HEX = "4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833";
static unsigned char TARGET[32];

static EC_GROUP *GRP;
static const EVP_MD *SHA512_MD;
static const char *WORDLIST[2048];

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

static void entropy_to_mnemonic(const unsigned char *ent, char out[256]) {
    unsigned char h[32];
    sha256(ent, 16, h);
    unsigned char bits[17];
    memcpy(bits, ent, 16);
    bits[16] = h[0];
    int pos = 0;
    out[0] = 0;
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

static __thread BN_CTX *g_ctx;
static __thread BIGNUM *t_order;

static void hex_print(const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

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
    if (n == 0) {
        out->k = BN_dup(root->k);
        memcpy(out->c, root->c, 32);
        return out->k != NULL;
    }
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

/* ------------------------------------------------------------- config */
typedef struct {
    unsigned offset;
    unsigned len;
    char     label[64];
} DigestCase;

static unsigned char *DIGEST_BLOB;
static size_t DIGEST_BLOB_LEN, DIGEST_BLOB_CAP;

static void digest_blob_add(const unsigned char *data, unsigned n) {
    if (DIGEST_BLOB_LEN + n > DIGEST_BLOB_CAP) {
        size_t cap = DIGEST_BLOB_CAP ? DIGEST_BLOB_CAP : 1 << 20;
        while (cap < DIGEST_BLOB_LEN + n) cap *= 2;
        unsigned char *nb = realloc(DIGEST_BLOB, cap);
        if (!nb) die("digest blob out of memory");
        DIGEST_BLOB = nb;
        DIGEST_BLOB_CAP = cap;
    }
    memcpy(DIGEST_BLOB + DIGEST_BLOB_LEN, data, n);
    DIGEST_BLOB_LEN += n;
}

typedef struct { uint32_t account; char label[64]; } AccountCase;

#define MAX_UNIQUE 64
typedef struct {
    uint32_t leaf[4];
    int      n;
    int      hard;
} LeafPath;

typedef struct {
    int ua, ub;
    char label[64];
} LeafCase;

static LeafPath  UNIQUE_LEAF[MAX_UNIQUE]; static int N_UNIQUE_LEAF;
static LeafCase  *LEAVES;  static int N_LEAF;
static DigestCase *DIGESTS; static int N_DIGEST;
static char **PASSES; static int N_PASS;
static AccountCase *ACCOUNTS; static int N_ACCT;

/* Precomputed per digest: entropy and mnemonic words. */
static unsigned char (*WORDS_ENT)[16];
static char (*WORDS)[256];

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) die("out of memory");
    return q;
}

static volatile int FOUND = 0;
static int MODE_ALLLEN = 0;
static pthread_mutex_t PRINT_LOCK = PTHREAD_MUTEX_INITIALIZER;

static int check_pair(const unsigned char *p1, const unsigned char *p2) {
    unsigned char script[71];
    script[0] = 0x52;
    script[1] = 33; memcpy(script + 2, p1, 33);
    script[35] = 33; memcpy(script + 36, p2, 33);
    script[69] = 0x52;
    script[70] = 0xae;
    unsigned char h[32];
    sha256(script, 71, h);
    return memcmp(h, TARGET, 32) == 0;
}

static void swapped(const unsigned char *a, const unsigned char *b,
                    unsigned char *oa, unsigned char *ob) {
    if (a[0] > b[0] || (a[0] == b[0] && memcmp(a, b, 33) > 0)) {
        memcpy(oa, b, 33); memcpy(ob, a, 33);
    } else {
        memcpy(oa, a, 33); memcpy(ob, b, 33);
    }
}

static void report_match(const DigestCase *da, const DigestCase *db,
                         const unsigned char *ent, const char *words,
                         int same_seed,
                         const char *pass, const AccountCase *acct,
                         const char *leaflab,
                         const unsigned char *k1, const unsigned char *k2) {
    pthread_mutex_lock(&PRINT_LOCK);
    if (!FOUND) {
        FOUND = 1;
        printf("MATCH\n");
        printf("  digest_a : %s\n", da->label);
        printf("  input_a  : ");
        for (unsigned i = 0; i < da->len; i++)
            putchar(DIGEST_BLOB[da->offset + i] >= 32 && DIGEST_BLOB[da->offset + i] < 127
                    ? DIGEST_BLOB[da->offset + i] : '.');
        printf("\n  digest_b : %s\n", db->label);
        printf("  input_b  : ");
        for (unsigned i = 0; i < db->len; i++)
            putchar(DIGEST_BLOB[db->offset + i] >= 32 && DIGEST_BLOB[db->offset + i] < 127
                    ? DIGEST_BLOB[db->offset + i] : '.');
        printf("\n  entropy_a: "); hex_print(ent, 16);
        printf("\n  words_a  : %s\n", words);
        printf("  same_seed: %s\n", same_seed ? "yes" : "no");
        printf("  pass     : %s\n", pass);
        printf("  account  : %u (%s)\n", acct->account, acct->label);
        printf("  leaves   : %s\n", leaflab);
        printf("  key_a    : "); hex_print(k1, 33);
        printf("\n  key_b    : "); hex_print(k2, 33);
        printf("\n");
        fflush(stdout);
    }
    pthread_mutex_unlock(&PRINT_LOCK);
}

/* Derive the pubkey at m/48'/0'/account'/2'/leaf for a seed. */
static int bip48_pub(const unsigned char seed[64], uint32_t account,
                     const LeafPath *lp, unsigned char out[33]) {
    Node root, base, acct, lf;
    node_master(&root, seed);
    uint32_t prefix[2] = {0x80000030u, 0x80000000u};
    int ok = node_path(&root, prefix, 2, &base);
    if (ok) {
        uint32_t tail[2] = {0x80000000u | account, 0x80000002u};
        ok = node_path(&base, tail, 2, &acct);
        if (ok) {
            uint32_t path[4];
            for (int i = 0; i < lp->n; i++)
                path[i] = lp->hard ? (lp->leaf[i] | 0x80000000u) : lp->leaf[i];
            ok = node_path(&acct, path, lp->n, &lf);
            if (ok) { ser_pub33(lf.k, out); node_free(&lf); }
        }
        node_free(&acct);
        node_free(&base);
    }
    node_free(&root);
    return ok;
}

/* ---- Key store: K[ai][pi][u][di] -> 33-byte pubkey (or zero if invalid) */
static unsigned char *K;

static unsigned char *key_at(int ai, int pi, int u, int di) {
    /* Layout: ((ai * N_PASS + pi) * N_UNIQUE_LEAF + u) * N_DIGEST + di keys */
    size_t idx = (((size_t)ai * N_PASS + pi) * (size_t)N_UNIQUE_LEAF + (size_t)u)
                 * (size_t)N_DIGEST + (size_t)di;
    return K + idx * 33;
}

typedef struct { int ai; long long checked; } P1Arg;

static void *phase1(void *arg) {
    P1Arg *a = arg;
    g_ctx = BN_CTX_new();
    t_order = BN_new();
    EC_GROUP_get_order(GRP, t_order, g_ctx);
    /* Flatten (di, passphrase, account) work items for balance. */
    long long items = (long long)N_DIGEST * N_PASS * N_ACCT;
    int nthreads = 2;
    for (long long w = a->ai; w < items && !FOUND; w += nthreads) {
        int di = (int)(w / ((long long)N_PASS * N_ACCT));
        int rem = (int)(w % ((long long)N_PASS * N_ACCT));
        int pi = rem / N_ACCT;
        int ai = rem % N_ACCT;
        char words[256];
        memcpy(words, WORDS[di], sizeof(words));
        unsigned char seed[64];
        pbkdf2_seed(words, PASSES[pi], seed);
        for (int u = 0; u < N_UNIQUE_LEAF; u++) {
            unsigned char *dest = key_at(ai, pi, u, di);
            if (!bip48_pub(seed, ACCOUNTS[ai].account, &UNIQUE_LEAF[u], dest))
                memset(dest, 0, 33);
        }
        if (getenv("ENGINE_PROGRESS") && di % 200 == 0 && ai == 0 && pi == 0) {
            static time_t last = 0;
            time_t now = time(NULL);
            if (last == 0 || now - last >= 20) {
                last = now;
                pthread_mutex_lock(&PRINT_LOCK);
                fprintf(stderr, "[progress] phase1 digest %d/%d\n", di, N_DIGEST);
                pthread_mutex_unlock(&PRINT_LOCK);
            }
        }
    }
    BN_free(t_order);
    BN_CTX_free(g_ctx);
    return NULL;
}

typedef struct { int id; long long checked; } P2Arg;

static void *phase2(void *arg) {
    P2Arg *a = arg;
    g_ctx = BN_CTX_new();
    t_order = BN_new();
    EC_GROUP_get_order(GRP, t_order, g_ctx);
    int nthreads = 2;
    for (int w = a->id; w < N_LEAF * N_ACCT * N_PASS && !FOUND; w += nthreads) {
        int pi = w % N_PASS;
        int ai = (w / N_PASS) % N_ACCT;
        int li = w / (N_PASS * N_ACCT);
        int ua = LEAVES[li].ua, ub = LEAVES[li].ub;
        long long local = 0;
        /* Pair digest indices; equal length unless MODE_ALLLEN. */
        for (int i = 0; i < N_DIGEST && !FOUND; i++) {
            const unsigned char *ka = key_at(ai, pi, ua, i);
            if ((ka[0] != 2 && ka[0] != 3)) continue;
            for (int j = i + 1; j < N_DIGEST && !FOUND; j++) {
                if (!MODE_ALLLEN && DIGESTS[i].len != DIGESTS[j].len) continue;
                const unsigned char *kb = key_at(ai, pi, ub, j);
                if (kb[0] != 2 && kb[0] != 3) continue;
                local++;
                if (check_pair(ka, kb)) {
                    report_match(&DIGESTS[i], &DIGESTS[j], WORDS_ENT[i], WORDS[i],
                                 0, PASSES[pi], &ACCOUNTS[ai], LEAVES[li].label, ka, kb);
                }
                unsigned char a1[33], b1[33];
                swapped(ka, kb, a1, b1);
                if (check_pair(a1, b1)) {
                    report_match(&DIGESTS[i], &DIGESTS[j], WORDS_ENT[i], WORDS[i],
                                 0, PASSES[pi], &ACCOUNTS[ai], LEAVES[li].label, ka, kb);
                }
            }
            /* Same-seed, same-pass, distinct leaf paths (same-root cosigners). */
            if (ua != ub) {
                const unsigned char *kb = key_at(ai, pi, ub, i);
                if (kb[0] == 2 || kb[0] == 3) {
                    if (memcmp(ka, kb, 33) != 0 && check_pair(ka, kb)) {
                        report_match(&DIGESTS[i], &DIGESTS[i], WORDS_ENT[i], WORDS[i],
                                     1, PASSES[pi], &ACCOUNTS[ai], LEAVES[li].label, ka, kb);
                    }
                    unsigned char a1[33], b1[33];
                    swapped(ka, kb, a1, b1);
                    if (memcmp(ka, kb, 33) != 0 && check_pair(a1, b1)) {
                        report_match(&DIGESTS[i], &DIGESTS[i], WORDS_ENT[i], WORDS[i],
                                     1, PASSES[pi], &ACCOUNTS[ai], LEAVES[li].label, ka, kb);
                    }
                }
            }
        }
        a->checked += local;
        if (getenv("ENGINE_PROGRESS")) {
            static time_t last = 0;
            time_t now = time(NULL);
            if (last == 0 || now - last >= 20) {
                last = now;
                pthread_mutex_lock(&PRINT_LOCK);
                fprintf(stderr, "[progress] phase2 leafcase %d/%d checked=%lld\n",
                        w, N_LEAF * N_ACCT * N_PASS, local);
                pthread_mutex_unlock(&PRINT_LOCK);
            }
        }
    }
    BN_free(t_order);
    BN_CTX_free(g_ctx);
    return NULL;
}

int main(void) {
    SHA512_MD = EVP_sha512();
    GRP = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const char *target_hex = getenv("ENGINE3_TARGET_HEX");
    if (!target_hex) target_hex = TARGET_HEX;
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(target_hex + 2 * i, "%2x", &v); TARGET[i] = (unsigned char)v;
    }
    load_wordlist("english.txt");
    if (getenv("ENGINE3_ALLLEN")) MODE_ALLLEN = 1;

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
                WORDS_ENT = xrealloc(WORDS_ENT, cap_d * sizeof(*WORDS_ENT));
                WORDS = xrealloc(WORDS, cap_d * sizeof(*WORDS));
            }
            char *hex = malloc((size_t)n * 2 + 1);
            for (int i = 0; i < n * 2; i++) {
                int c = fgetc(stdin);
                if (c == EOF) die("short D payload");
                hex[i] = (char)c;
            }
            hex[n * 2] = 0;
            fgetc(stdin);
            if ((int)strlen(hex) != n * 2) die("bad D hex length");
            unsigned char *raw = malloc((size_t)n ? (size_t)n : 1);
            for (int i = 0; i < n; i++) {
                unsigned v; sscanf(hex + 2 * i, "%2x", &v);
                raw[i] = (unsigned char)v;
            }
            DIGESTS[N_DIGEST].offset = (unsigned)DIGEST_BLOB_LEN;
            DIGESTS[N_DIGEST].len = (unsigned)n;
            digest_blob_add(raw, (unsigned)n);
            snprintf(DIGESTS[N_DIGEST].label, 64, "%s", label);
            N_DIGEST++;
            free(raw); free(hex);
        } else if (kind == 'P') {
            if (N_PASS == cap_p) {
                cap_p = cap_p ? cap_p * 2 : 32;
                PASSES = xrealloc(PASSES, cap_p * sizeof(char *));
            }
            PASSES[N_PASS] = strdup(line + 2);
            char *nl = strchr(PASSES[N_PASS], '\n');
            if (nl) *nl = 0;
            N_PASS++;
        } else if (kind == 'A') {
            if (N_ACCT == cap_a) {
                cap_a = cap_a ? cap_a * 2 : 32;
                ACCOUNTS = xrealloc(ACCOUNTS, cap_a * sizeof(AccountCase));
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
            }
            char label[64]; int na, nb; char hard[8] = "nh";
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
            sscanf(p, "%7s", hard);
            int ua = -1, ub = -1;
            for (int u = 0; u < N_UNIQUE_LEAF; u++) {
                if (UNIQUE_LEAF[u].n != na) continue;
                if (UNIQUE_LEAF[u].hard != (strcmp(hard, "h") == 0)) continue;
                if (memcmp(UNIQUE_LEAF[u].leaf, tmp, sizeof(uint32_t) * na) == 0) { ua = u; break; }
            }
            if (ua < 0) {
                ua = N_UNIQUE_LEAF++;
                UNIQUE_LEAF[ua].n = na;
                UNIQUE_LEAF[ua].hard = (strcmp(hard, "h") == 0);
                memcpy(UNIQUE_LEAF[ua].leaf, tmp, sizeof(uint32_t) * na);
            }
            for (int u = 0; u < N_UNIQUE_LEAF; u++) {
                if (UNIQUE_LEAF[u].n != nb) continue;
                if (UNIQUE_LEAF[u].hard != (strcmp(hard, "h") == 0)) continue;
                if (memcmp(UNIQUE_LEAF[u].leaf, tmp2, sizeof(uint32_t) * nb) == 0) { ub = u; break; }
            }
            if (ub < 0) {
                ub = N_UNIQUE_LEAF++;
                UNIQUE_LEAF[ub].n = nb;
                UNIQUE_LEAF[ub].hard = (strcmp(hard, "h") == 0);
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
    fprintf(stderr, "engine3: digests=%d passes=%d accounts=%d leaves=%d uniquepaths=%d all_len=%d\n",
            N_DIGEST, N_PASS, N_ACCT, N_LEAF, N_UNIQUE_LEAF, MODE_ALLLEN);

    /* Precompute words for every digest. */
    for (int di = 0; di < N_DIGEST; di++) {
        unsigned char h[32];
        sha256(DIGEST_BLOB + DIGESTS[di].offset, DIGESTS[di].len, h);
        memcpy(WORDS_ENT[di], h, 16);
        /* entropy = first 32 hex chars of sha256sum == first 16 bytes */
        entropy_to_mnemonic(WORDS_ENT[di], WORDS[di]);
    }

    size_t total = (size_t)N_ACCT * N_PASS * N_UNIQUE_LEAF * N_DIGEST;
    K = xrealloc(K, total * 33);
    memset(K, 0, total * 33);
    fprintf(stderr, "engine3: key store %.1f MB\n", total * 33 / 1048576.0);

    int nthreads = 2;
    pthread_t th[16];
    P1Arg a1[16];
    for (int i = 0; i < nthreads; i++) { a1[i].ai = i; a1[i].checked = 0; pthread_create(&th[i], NULL, phase1, &a1[i]); }
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);

    P2Arg a2[16];
    for (int i = 0; i < nthreads; i++) { a2[i].id = i; a2[i].checked = 0; pthread_create(&th[i], NULL, phase2, &a2[i]); }
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    long long total_checks = 0;
    for (int i = 0; i < nthreads; i++) total_checks += a2[i].checked;
    if (!FOUND) printf("NO_MATCH checked=%lld\n", total_checks);
    if (getenv("ENGINE3_DEBUG_KEYS")) {
        for (int ai = 0; ai < N_ACCT && ai < 2; ai++)
            for (int pi = 0; pi < N_PASS && pi < 2; pi++)
                for (int u = 0; u < N_UNIQUE_LEAF; u++)
                    for (int di = 0; di < N_DIGEST && di < 2; di++) {
                        unsigned char *k = key_at(ai, pi, u, di);
                        fprintf(stderr, "ai=%d pi=%d u=%d di=%d k=", ai, pi, u, di);
                        for (int b = 0; b < 33; b++) fprintf(stderr, "%02x", k[b]);
                        fprintf(stderr, "\n");
                    }
    }
    return FOUND ? 0 : 1;
}
