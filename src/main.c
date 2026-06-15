/* Multi Ciphers - dependency-free file encryption CLI.
 *
 * Ciphers : AES-256-GCM, XChaCha20-Poly1305, Serpent-256-GCM
 * KDF     : Argon2id (low / medium / high strength profiles)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>

#include "aes.h"
#include "serpent.h"
#include "gcm.h"
#include "chacha20poly1305.h"
#include "argon2.h"
#include "random.h"

#define MC_VERSION "1.0.3"

/* ---- container format ---- */
#define MC_MAGIC0 'M'
#define MC_MAGIC1 'C'
#define MC_MAGIC2 'P'
#define MC_MAGIC3 'H'
#define MC_FORMAT_VERSION 1

#define HDR_LEN   60
#define SALT_LEN  16
#define NONCE_LEN 24
#define TAG_LEN   16
#define KEY_LEN   32

enum { CIPHER_AES = 1, CIPHER_XCHACHA = 2, CIPHER_SERPENT = 3 };
enum { KDF_ARGON2ID = 1 };
enum { STR_LOW = 1, STR_MEDIUM = 2, STR_HIGH = 3 };

typedef struct {
    uint32_t t_cost, m_cost, lanes;
} argon_params;

static argon_params profile_for(int strength) {
    argon_params p;
    switch (strength) {
    case STR_LOW:    p.t_cost = 3; p.m_cost = 64u * 1024;        p.lanes = 1; break; /* 64 MiB */
    case STR_HIGH:   p.t_cost = 4; p.m_cost = 2u * 1024 * 1024;  p.lanes = 8; break; /* 2 GiB  */
    case STR_MEDIUM:
    default:         p.t_cost = 3; p.m_cost = 1u * 1024 * 1024;  p.lanes = 4; break; /* 1 GiB  */
    }
    return p;
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static uint32_t get_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

/* ---- block-cipher adapters for GCM ---- */
static void aes_blk(const void *c, const uint8_t in[16], uint8_t out[16]) {
    aes256_encrypt_block((const aes256_ctx *)c, in, out);
}
static void serpent_blk(const void *c, const uint8_t in[16], uint8_t out[16]) {
    serpent_encrypt_block((const serpent_ctx *)c, in, out);
}

/* ---- helpers ---- */
static int read_file(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *b = malloc((size_t)sz ? (size_t)sz : 1);
    if (!b) { fclose(f); return -1; }
    if (sz > 0 && fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return -1; }
    fclose(f);
    *buf = b; *len = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    if (fclose(f) != 0) return -1;
    return 0;
}

static int read_password(const char *prompt, char *out, size_t cap) {
    struct termios old, noecho;
    FILE *tty = fopen("/dev/tty", "r+");
    FILE *in = tty ? tty : stdin;
    int have_tty = isatty(fileno(in));

    fputs(prompt, stderr);
    fflush(stderr);

    if (have_tty) {
        tcgetattr(fileno(in), &old);
        noecho = old;
        noecho.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fileno(in), TCSAFLUSH, &noecho);
    }
    char *r = fgets(out, (int)cap, in);
    if (have_tty) {
        tcsetattr(fileno(in), TCSAFLUSH, &old);
        fputs("\n", stderr);
    }
    if (tty) fclose(tty);
    if (!r) return -1;
    size_t n = strlen(out);
    while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = 0;
    return 0;
}

static int derive_key(uint8_t key[KEY_LEN], const char *pwd,
                      const uint8_t salt[SALT_LEN], argon_params p) {
    fprintf(stderr, "Deriving key (Argon2id, m=%u MiB, t=%u, lanes=%u)...\n",
            p.m_cost / 1024, p.t_cost, p.lanes);
    return argon2id_hash(key, KEY_LEN, pwd, strlen(pwd),
                         salt, SALT_LEN, p.t_cost, p.m_cost, p.lanes);
}

/* ---- encrypt ---- */
static int do_encrypt(const char *in_path, const char *out_path,
                      int cipher, int strength, const char *pwd_opt) {
    uint8_t *pt = NULL; size_t ptlen = 0;
    if (read_file(in_path, &pt, &ptlen) != 0) {
        fprintf(stderr, "error: cannot read input file '%s'\n", in_path);
        return 1;
    }

    char pwd[1024], pwd2[1024];
    if (pwd_opt) {
        strncpy(pwd, pwd_opt, sizeof(pwd) - 1); pwd[sizeof(pwd)-1] = 0;
    } else {
        if (read_password("Password: ", pwd, sizeof(pwd)) != 0 ||
            read_password("Confirm password: ", pwd2, sizeof(pwd2)) != 0) {
            fprintf(stderr, "error: could not read password\n"); free(pt); return 1;
        }
        if (strcmp(pwd, pwd2) != 0) {
            fprintf(stderr, "error: passwords do not match\n");
            free(pt); return 1;
        }
        memset(pwd2, 0, sizeof(pwd2));
    }

    argon_params p = profile_for(strength);
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN];
    if (mc_random_bytes(salt, SALT_LEN) || mc_random_bytes(nonce, NONCE_LEN)) {
        fprintf(stderr, "error: RNG failure\n"); free(pt); return 1;
    }

    uint8_t hdr[HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    hdr[0]=MC_MAGIC0; hdr[1]=MC_MAGIC1; hdr[2]=MC_MAGIC2; hdr[3]=MC_MAGIC3;
    hdr[4]=MC_FORMAT_VERSION;
    hdr[5]=(uint8_t)cipher;
    hdr[6]=KDF_ARGON2ID;
    hdr[7]=(uint8_t)strength;
    put_le32(hdr+8,  p.t_cost);
    put_le32(hdr+12, p.m_cost);
    put_le32(hdr+16, p.lanes);
    memcpy(hdr+20, salt, SALT_LEN);
    memcpy(hdr+36, nonce, NONCE_LEN);

    if (derive_key(key, pwd, salt, p) != 0) {
        fprintf(stderr, "error: key derivation failed\n");
        memset(pwd,0,sizeof(pwd)); free(pt); return 1;
    }
    memset(pwd, 0, sizeof(pwd));

    uint8_t *ct = malloc(ptlen ? ptlen : 1);
    uint8_t tag[TAG_LEN];
    if (!ct) { fprintf(stderr, "error: out of memory\n"); free(pt); return 1; }

    if (cipher == CIPHER_AES) {
        aes256_ctx c; aes256_init(&c, key);
        gcm_encrypt(aes_blk, &c, nonce, hdr, HDR_LEN, pt, ptlen, ct, tag);
        memset(&c, 0, sizeof(c));
    } else if (cipher == CIPHER_SERPENT) {
        serpent_ctx c; serpent_setkey(&c, key, KEY_LEN);
        gcm_encrypt(serpent_blk, &c, nonce, hdr, HDR_LEN, pt, ptlen, ct, tag);
        memset(&c, 0, sizeof(c));
    } else { /* XChaCha20-Poly1305 */
        xchacha20poly1305_encrypt(ct, tag, pt, ptlen, hdr, HDR_LEN, nonce, key);
    }
    memset(key, 0, sizeof(key));

    /* assemble output: header || ciphertext || tag */
    size_t outlen = HDR_LEN + ptlen + TAG_LEN;
    uint8_t *out = malloc(outlen);
    if (!out) { fprintf(stderr,"error: out of memory\n"); free(pt); free(ct); return 1; }
    memcpy(out, hdr, HDR_LEN);
    memcpy(out + HDR_LEN, ct, ptlen);
    memcpy(out + HDR_LEN + ptlen, tag, TAG_LEN);

    int rc = write_file(out_path, out, outlen);
    free(pt); free(ct); free(out);
    if (rc != 0) { fprintf(stderr, "error: cannot write '%s'\n", out_path); return 1; }
    fprintf(stderr, "Encrypted %zu bytes -> %s\n", ptlen, out_path);
    return 0;
}

/* ---- decrypt ---- */
static int do_decrypt(const char *in_path, const char *out_path, const char *pwd_opt) {
    uint8_t *blob = NULL; size_t blen = 0;
    if (read_file(in_path, &blob, &blen) != 0) {
        fprintf(stderr, "error: cannot read input file '%s'\n", in_path); return 1;
    }
    if (blen < HDR_LEN + TAG_LEN) {
        fprintf(stderr, "error: file too short / not a Multi Ciphers file\n");
        free(blob); return 1;
    }
    const uint8_t *hdr = blob;
    if (!(hdr[0]==MC_MAGIC0 && hdr[1]==MC_MAGIC1 && hdr[2]==MC_MAGIC2 && hdr[3]==MC_MAGIC3)) {
        fprintf(stderr, "error: bad magic (not a Multi Ciphers file)\n"); free(blob); return 1;
    }
    if (hdr[4] != MC_FORMAT_VERSION) {
        fprintf(stderr, "error: unsupported format version %u\n", hdr[4]); free(blob); return 1;
    }
    int cipher = hdr[5];
    if (cipher != CIPHER_AES && cipher != CIPHER_XCHACHA && cipher != CIPHER_SERPENT) {
        fprintf(stderr, "error: unknown cipher id %d\n", cipher); free(blob); return 1;
    }
    if (hdr[6] != KDF_ARGON2ID) {
        fprintf(stderr, "error: unsupported KDF id %u\n", hdr[6]); free(blob); return 1;
    }
    argon_params p;
    p.t_cost = get_le32(hdr+8);
    p.m_cost = get_le32(hdr+12);
    p.lanes  = get_le32(hdr+16);
    const uint8_t *salt  = hdr + 20;
    const uint8_t *nonce = hdr + 36;

    const uint8_t *ct = blob + HDR_LEN;
    size_t ctlen = blen - HDR_LEN - TAG_LEN;
    const uint8_t *tag = blob + HDR_LEN + ctlen;

    char pwd[1024];
    if (pwd_opt) { strncpy(pwd, pwd_opt, sizeof(pwd)-1); pwd[sizeof(pwd)-1]=0; }
    else if (read_password("Password: ", pwd, sizeof(pwd)) != 0) {
        fprintf(stderr, "error: could not read password\n"); free(blob); return 1;
    }

    uint8_t key[KEY_LEN];
    if (derive_key(key, pwd, salt, p) != 0) {
        fprintf(stderr, "error: key derivation failed\n");
        memset(pwd,0,sizeof(pwd)); free(blob); return 1;
    }
    memset(pwd, 0, sizeof(pwd));

    uint8_t *pt = malloc(ctlen ? ctlen : 1);
    if (!pt) { fprintf(stderr,"error: out of memory\n"); free(blob); return 1; }

    int rc;
    if (cipher == CIPHER_AES) {
        aes256_ctx c; aes256_init(&c, key);
        rc = gcm_decrypt(aes_blk, &c, nonce, hdr, HDR_LEN, ct, ctlen, tag, pt);
        memset(&c, 0, sizeof(c));
    } else if (cipher == CIPHER_SERPENT) {
        serpent_ctx c; serpent_setkey(&c, key, KEY_LEN);
        rc = gcm_decrypt(serpent_blk, &c, nonce, hdr, HDR_LEN, ct, ctlen, tag, pt);
        memset(&c, 0, sizeof(c));
    } else if (cipher == CIPHER_XCHACHA) {
        rc = xchacha20poly1305_decrypt(pt, ct, ctlen, tag, hdr, HDR_LEN, nonce, key);
    } else {
        fprintf(stderr, "error: unknown cipher id %d\n", cipher);
        memset(key,0,sizeof(key)); free(blob); free(pt); return 1;
    }
    memset(key, 0, sizeof(key));

    if (rc != 0) {
        fprintf(stderr, "error: authentication failed (wrong password or corrupted file)\n");
        free(blob); free(pt); return 1;
    }

    rc = write_file(out_path, pt, ctlen);
    free(blob); free(pt);
    if (rc != 0) { fprintf(stderr, "error: cannot write '%s'\n", out_path); return 1; }
    fprintf(stderr, "Decrypted %zu bytes -> %s\n", ctlen, out_path);
    return 0;
}

/* ---- self test (declared in selftest.c) ---- */
int mc_selftest(void);

/* ---- interactive menu ---- */
static int prompt_line(const char *prompt, char *out, size_t cap) {
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(out, (int)cap, stdin)) return -1;
    size_t n = strlen(out);
    while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = 0;
    return 0;
}

static const char *cipher_name(int c); /* fwd decl */

/* Cipher-selection sub-menu. Returns a CIPHER_* id (0 if cancelled). */
static int choose_cipher(void) {
    char buf[64];
    for (;;) {
        fprintf(stderr,
            "\n--- Choose cipher ---------------------------\n"
            "  1) AES-256-GCM          (default)\n"
            "  2) XChaCha20-Poly1305\n"
            "  3) Serpent-256-GCM\n"
            "  0) Cancel\n");
        if (prompt_line("Cipher [1]: ", buf, sizeof(buf)) != 0) return CIPHER_AES;
        if (buf[0] == 0)   return CIPHER_AES;     /* Enter = default */
        if (buf[0] == '1') return CIPHER_AES;
        if (buf[0] == '2') return CIPHER_XCHACHA;
        if (buf[0] == '3') return CIPHER_SERPENT;
        if (buf[0] == '0') return 0;
        fprintf(stderr, "Please enter 0, 1, 2 or 3.\n");
    }
}

/* Argon2id strength sub-menu. Returns a STR_* id (0 if cancelled). */
static int choose_strength(void) {
    char buf[64];
    for (;;) {
        fprintf(stderr,
            "\n--- Choose Argon2id strength ----------------\n"
            "  1) low      64 MiB,  t=3, 1 lane\n"
            "  2) medium   1 GiB,   t=3, 4 lanes   (default)\n"
            "  3) high     2 GiB,   t=4, 8 lanes\n"
            "  0) Cancel\n");
        if (prompt_line("Strength [2]: ", buf, sizeof(buf)) != 0) return STR_MEDIUM;
        if (buf[0] == 0)   return STR_MEDIUM;     /* Enter = default */
        if (buf[0] == '1') return STR_LOW;
        if (buf[0] == '2') return STR_MEDIUM;
        if (buf[0] == '3') return STR_HIGH;
        if (buf[0] == '0') return 0;
        fprintf(stderr, "Please enter 0, 1, 2 or 3.\n");
    }
}

static int menu_encrypt(void) {
    char in[1024], out[1024];
    int cipher, strength;

    if (prompt_line("Input file to encrypt: ", in, sizeof(in)) || !in[0]) {
        fprintf(stderr, "cancelled.\n"); return 1;
    }
    if (prompt_line("Output file: ", out, sizeof(out)) || !out[0]) {
        fprintf(stderr, "cancelled.\n"); return 1;
    }

    cipher = choose_cipher();
    if (cipher == 0) { fprintf(stderr, "cancelled.\n"); return 1; }

    strength = choose_strength();
    if (strength == 0) { fprintf(stderr, "cancelled.\n"); return 1; }

    fprintf(stderr, "\nCipher: %s\n", cipher_name(cipher));
    return do_encrypt(in, out, cipher, strength, NULL);
}

static int menu_decrypt(void) {
    char in[1024], out[1024];
    if (prompt_line("Input file to decrypt: ", in, sizeof(in)) || !in[0]) {
        fprintf(stderr, "cancelled.\n"); return 1;
    }
    if (prompt_line("Output file: ", out, sizeof(out)) || !out[0]) {
        fprintf(stderr, "cancelled.\n"); return 1;
    }
    return do_decrypt(in, out, NULL);
}

static void usage(FILE *f, const char *prog); /* fwd decl */

static int interactive_menu(const char *prog) {
    char buf[64];
    for (;;) {
        fprintf(stderr,
            "\n=============================================\n"
            "  Multi Ciphers %s  -  interactive menu\n"
            "=============================================\n"
            "  1) Encrypt a file\n"
            "  2) Decrypt a file\n"
            "  3) Run self-test\n"
            "  4) Help / command-line usage\n"
            "  5) Quit\n",
            MC_VERSION);
        if (prompt_line("Choose an option [1-5]: ", buf, sizeof(buf)) != 0) return 0;
        switch (buf[0]) {
        case '1': menu_encrypt(); break;
        case '2': menu_decrypt(); break;
        case '3': mc_selftest(); break;
        case '4': usage(stderr, prog); break;
        case '5': case 'q': case 'Q': return 0;
        default: fprintf(stderr, "Please enter a number from 1 to 5.\n");
        }
    }
}

/* ---- CLI ---- */
static const char *cipher_name(int c) {
    switch (c) {
    case CIPHER_AES: return "AES-256-GCM";
    case CIPHER_XCHACHA: return "XChaCha20-Poly1305";
    case CIPHER_SERPENT: return "Serpent-256-GCM";
    default: return "?";
    }
}

static void usage(FILE *f, const char *prog) {
    fprintf(f,
"Multi Ciphers %s - dependency-free authenticated file encryption\n"
"\n"
"Usage:\n"
"  %s encrypt -i <in> -o <out> [-c <cipher>] [-s <strength>] [-p <password>]\n"
"  %s decrypt -i <in> -o <out> [-p <password>]\n"
"  %s selftest\n"
"  %s --version | --help\n"
"\n"
"Ciphers (-c):   aes        AES-256-GCM (default)\n"
"                xchacha    XChaCha20-Poly1305\n"
"                serpent    Serpent-256-GCM\n"
"\n"
"Argon2id strength (-s):\n"
"                low        64 MiB,  t=3, 1 lane\n"
"                medium     1 GiB,   t=3, 4 lanes   (default)\n"
"                high       2 GiB,   t=4, 8 lanes\n"
"\n"
"If -p is omitted the password is read interactively (no echo).\n"
"Cipher and strength are stored in the file header and applied on decrypt.\n",
        MC_VERSION, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) return interactive_menu(argv[0]);
    if (!strcmp(argv[1], "menu")) return interactive_menu(argv[0]);

    if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-v")) {
        printf("Multi Ciphers %s\n", MC_VERSION);
        return 0;
    }
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage(stdout, argv[0]); return 0;
    }
    if (!strcmp(argv[1], "selftest")) {
        return mc_selftest();
    }

    int mode = 0;
    if (!strcmp(argv[1], "encrypt")) mode = 1;
    else if (!strcmp(argv[1], "decrypt")) mode = 2;
    else { fprintf(stderr, "error: unknown command '%s'\n\n", argv[1]); usage(stderr, argv[0]); return 2; }

    const char *in = NULL, *out = NULL, *pwd = NULL;
    int cipher = CIPHER_AES, strength = STR_MEDIUM;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-i") && i+1 < argc) in = argv[++i];
        else if (!strcmp(a, "-o") && i+1 < argc) out = argv[++i];
        else if (!strcmp(a, "-p") && i+1 < argc) pwd = argv[++i];
        else if (!strcmp(a, "-c") && i+1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v,"aes")) cipher = CIPHER_AES;
            else if (!strcmp(v,"xchacha")||!strcmp(v,"xchacha20")) cipher = CIPHER_XCHACHA;
            else if (!strcmp(v,"serpent")) cipher = CIPHER_SERPENT;
            else { fprintf(stderr, "error: unknown cipher '%s'\n", v); return 2; }
        }
        else if (!strcmp(a, "-s") && i+1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v,"low")) strength = STR_LOW;
            else if (!strcmp(v,"medium")) strength = STR_MEDIUM;
            else if (!strcmp(v,"high")) strength = STR_HIGH;
            else { fprintf(stderr, "error: unknown strength '%s'\n", v); return 2; }
        }
        else { fprintf(stderr, "error: unexpected argument '%s'\n", a); return 2; }
    }

    if (!in || !out) {
        fprintf(stderr, "error: -i and -o are required\n\n");
        usage(stderr, argv[0]); return 2;
    }

    if (mode == 1) {
        fprintf(stderr, "Cipher: %s\n", cipher_name(cipher));
        return do_encrypt(in, out, cipher, strength, pwd);
    }
    return do_decrypt(in, out, pwd);
}
