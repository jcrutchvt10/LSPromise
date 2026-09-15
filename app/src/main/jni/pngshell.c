// pngshell.c - standalone shell probe: decode paletted PNG via device
// libpng with per-row mallocs + canaries. Detects CVE-2026-33636 NEON
// palette OOB without Skia. Run: pngshell <file.png> <label>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <dlfcn.h>

typedef void *png_structp;
typedef void *png_infop;
typedef unsigned char png_byte;
typedef png_byte *png_bytep;
typedef png_byte **png_bytepp;
typedef unsigned int png_uint_32;
typedef unsigned long png_size_t;

typedef struct {
    const unsigned char *p;
    size_t left;
    jmp_buf jmp;
    char err[256];
} ctx_t;

static ctx_t *g_ctx = NULL;

static void pt_read(png_structp ps, png_bytep out, png_size_t n) {
    (void)ps;
    if (!g_ctx || n > g_ctx->left) {
        if (g_ctx) { snprintf(g_ctx->err, sizeof(g_ctx->err), "short read"); longjmp(g_ctx->jmp, 1); }
        return;
    }
    memcpy(out, g_ctx->p, n);
    g_ctx->p += n;
    g_ctx->left -= n;
}

static void pt_error(png_structp ps, const char *msg) {
    (void)ps;
    if (g_ctx) {
        snprintf(g_ctx->err, sizeof(g_ctx->err), "%.200s", msg ? msg : "?");
        longjmp(g_ctx->jmp, 1);
    }
}

static void pt_warn(png_structp ps, const char *msg) { (void)ps; (void)msg; }

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: pngshell <file> <label>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { printf("%s: cannot open %s\n", argv[2], argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(len);
    if (!buf) return 2;
    if (fread(buf, 1, len, f) != (size_t)len) return 2;
    fclose(f);

    void *h = dlopen("/system/lib64/libpng.so", RTLD_NOW);
    if (!h) { printf("%s: dlopen failed: %s\n", argv[2], dlerror()); return 2; }
#define SYM(t, n) t = dlsym(h, n); if (!t) { printf("%s: dlsym %s failed\n", argv[2], n); return 2; }
    png_structp (*p_create_read)(const char *, void *,
        void (*)(png_structp, const char *), void (*)(png_structp, const char *));
    void *(*p_create_info)(png_structp);
    void (*p_destroy)(png_structp *, void *, void *);
    void (*p_set_error_fn)(png_structp, void *,
        void (*)(png_structp, const char *), void (*)(png_structp, const char *));
    void (*p_set_read_fn)(png_structp, void *,
        void (*)(png_structp, png_bytep, png_size_t));
    void (*p_read_info)(png_structp, void *);
    png_uint_32 (*p_get_w)(png_structp, void *);
    png_uint_32 (*p_get_h)(png_structp, void *);
    int (*p_get_ct)(png_structp, void *);
    int (*p_get_bd)(png_structp, void *);
    png_size_t (*p_get_rb)(png_structp, void *);
    void (*p_strip16)(png_structp);
    void (*p_packing)(png_structp);
    void (*p_expand)(png_structp);
    void (*p_pal2rgb)(png_structp);
    void (*p_trns2a)(png_structp);
    void (*p_gray2rgb)(png_structp);
    void (*p_upd)(png_structp, void *);
    void (*p_read_img)(png_structp, png_bytepp);
    SYM(p_create_read, "png_create_read_struct");
    SYM(p_create_info, "png_create_info_struct");
    SYM(p_destroy, "png_destroy_read_struct");
    SYM(p_set_error_fn, "png_set_error_fn");
    SYM(p_set_read_fn, "png_set_read_fn");
    SYM(p_read_info, "png_read_info");
    SYM(p_get_w, "png_get_image_width");
    SYM(p_get_h, "png_get_image_height");
    SYM(p_get_ct, "png_get_color_type");
    SYM(p_get_bd, "png_get_bit_depth");
    SYM(p_get_rb, "png_get_rowbytes");
    SYM(p_strip16, "png_set_strip_16");
    SYM(p_packing, "png_set_packing");
    SYM(p_expand, "png_set_expand");
    SYM(p_pal2rgb, "png_set_palette_to_rgb");
    SYM(p_trns2a, "png_set_tRNS_to_alpha");
    SYM(p_gray2rgb, "png_set_gray_to_rgb");
    SYM(p_upd, "png_read_update_info");
    SYM(p_read_img, "png_read_image");

    ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.p = buf;
    ctx.left = len;
    g_ctx = &ctx;
    if (setjmp(ctx.jmp)) {
        printf("%s: libpng error: %s\n", argv[2], ctx.err);
        return 1;
    }
    png_structp ps = p_create_read("1.6.51", NULL, NULL, NULL);
    void *pi = p_create_info(ps);
    p_set_error_fn(ps, NULL, pt_error, pt_warn);
    p_set_read_fn(ps, NULL, pt_read);
    p_read_info(ps, pi);
    png_uint_32 w = p_get_w(ps, pi), hh = p_get_h(ps, pi);
    int ct = p_get_ct(ps, pi), bd = p_get_bd(ps, pi);
    p_strip16(ps); p_packing(ps); p_expand(ps);
    p_pal2rgb(ps); p_trns2a(ps); p_gray2rgb(ps);
    p_upd(ps, pi);
    png_size_t rb = p_get_rb(ps, pi);

    png_bytepp rows = malloc(hh * sizeof(png_bytep));
    unsigned char *bufs = malloc(hh * (rb + 64));
    if (!rows || !bufs) { printf("%s: row alloc failed\n", argv[2]); return 2; }
    for (png_uint_32 y = 0; y < hh; y++) {
        unsigned char *b = bufs + y * (rb + 64);
        memset(b, 0xAA, 32);
        memset(b + 32 + rb, 0xBB, 32);
        rows[y] = b + 32;
    }
    p_read_img(ps, rows);

    int badRows = 0, firstBad = -1, headBad = 0;
    size_t maxOver = 0;
    for (png_uint_32 y = 0; y < hh; y++) {
        unsigned char *b = bufs + y * (rb + 64);
        for (int i = 0; i < 32; i++) if (b[i] != 0xAA) { headBad = 1; break; }
        size_t first = 0;
        while (first < 32 && b[32 + rb + first] == 0xBB) first++;
        if (first < 32) {
            badRows++;
            if (firstBad < 0) firstBad = y;
            if (32 - first > maxOver) maxOver = 32 - first;
        }
    }
    printf("%s: %ux%u ct=%d bd=%d rowbytes=%u rows=%u badRows=%d firstBad=%d maxOverrun=%zu headBad=%d %s\n",
            argv[2], w, hh, ct, bd, (unsigned)rb, (unsigned)hh,
            badRows, firstBad, maxOver, headBad,
            (badRows > 0 ? "VULNERABLE PATH CONFIRMED" : "canaries intact"));
    // dump row0 bytes for render-corruption comparison (NEON underflow
    // clobbers pixels but stays inside libpng's internal row_buf, so our
    // canaries stay intact while output pixels go wrong)
    if (hh > 0) {
        printf("%s-row0:", argv[2]);
        for (png_size_t i = 0; i < rb && i < 64; i++) printf("%02x", rows[0][i]);
        printf("\n");
    }
    png_structp ps2 = ps; void *pi2 = pi;
    p_destroy(&ps2, &pi2, NULL);
    free(rows); free(bufs); free(buf);
    return 0;
}
