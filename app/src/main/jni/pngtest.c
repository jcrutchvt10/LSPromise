// pngtest.c - isolate device libpng: decode paletted PNG with per-row
// mallocs + canaries to detect the NEON palette OOB (CVE-2026-33636)
// without Skia in the loop. Safe probe: reports, never exploits.
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "LSPromise", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "LSPromise", __VA_ARGS__)

typedef void *png_structp;
typedef void *png_infop;
typedef unsigned char png_byte;
typedef png_byte *png_bytep;
typedef png_byte **png_bytepp;
typedef unsigned int png_uint_32;
typedef unsigned long png_size_t;

typedef png_structp (*fn_create_read)(const char *, void *,
        void (*)(png_structp, const char *), void (*)(png_structp, const char *));
typedef png_infop (*fn_create_info)(png_structp);
typedef void (*fn_destroy)(png_structp *, png_infop *, png_infop *);
typedef void (*fn_set_error_fn)(png_structp, void *,
        void (*)(png_structp, const char *), void (*)(png_structp, const char *));
typedef void (*fn_set_read_fn)(png_structp, void *,
        void (*)(png_structp, png_bytep, png_size_t));
typedef void (*fn_read_info)(png_structp, png_infop);
typedef png_uint_32 (*fn_get_u32)(png_structp, png_infop);
typedef int (*fn_get_int)(png_structp, png_infop);
typedef png_size_t (*fn_get_rowbytes)(png_structp, png_infop);
typedef void (*fn_void_p)(png_structp);
typedef void (*fn_read_update)(png_structp, png_infop);
typedef void (*fn_read_image)(png_structp, png_bytepp);

typedef struct {
    const unsigned char *p;
    size_t left;
    jmp_buf jmp;
    char err[256];
} pngtest_ctx;

static void pt_read(png_structp ps, png_bytep out, png_size_t n) {
    (void)ps;
    pngtest_ctx *c = NULL;
    // io_ptr is fetched via dlsym'd png_get_io_ptr below (stored globally)
    extern pngtest_ctx *g_ctx;
    c = g_ctx;
    if (!c || n > c->left) {
        if (c) { snprintf(c->err, sizeof(c->err), "short read"); longjmp(c->jmp, 1); }
        return;
    }
    memcpy(out, c->p, n);
    c->p += n;
    c->left -= n;
}

static void pt_error(png_structp ps, const char *msg) {
    (void)ps;
    extern pngtest_ctx *g_ctx;
    if (g_ctx) {
        snprintf(g_ctx->err, sizeof(g_ctx->err), "%.200s", msg ? msg : "?");
        longjmp(g_ctx->jmp, 1);
    }
}

static void pt_warn(png_structp ps, const char *msg) {
    (void)ps; (void)msg;
}

pngtest_ctx *g_ctx = NULL;

#define LOAD(h, t, n) do { p_##t = (fn_##t)dlsym(h, n); \
    if (!p_##t) { snprintf(out, sizeof(tmp), "dlsym failed: %s", n); goto done; } } while (0)

JNIEXPORT jstring JNICALL
Java_org_lsposed_lspromise_PngTest_runTest(JNIEnv *env, jclass clz,
        jbyteArray pngData, jstring labelJ) {
    (void)clz;
    char tmp[1024], out[2048];
    out[0] = 0;
    const char *label = (*env)->GetStringUTFChars(env, labelJ, NULL);

    jsize pngLen = (*env)->GetArrayLength(env, pngData);
    unsigned char *pngBuf = malloc(pngLen);
    if (!pngBuf) return (*env)->NewStringUTF(env, "oom");
    (*env)->GetByteArrayRegion(env, pngData, 0, pngLen, (jbyte *)pngBuf);

    void *h = dlopen("libpng.so", RTLD_NOW);
    if (!h) h = dlopen("/system/lib64/libpng.so", RTLD_NOW);
    if (!h) { snprintf(out, sizeof(out), "%s: dlopen failed", label); goto done; }

    fn_create_read p_create_read; fn_create_info p_create_info;
    fn_destroy p_destroy; fn_set_error_fn p_set_error_fn;
    fn_set_read_fn p_set_read_fn; fn_read_info p_read_info;
    fn_get_u32 p_get_w, p_get_h; fn_get_int p_get_ct, p_get_bd;
    fn_get_rowbytes p_get_rb; fn_void_p p_strip16, p_packing, p_expand,
            p_pal2rgb, p_trns2a, p_gray2rgb;
    fn_read_update p_upd; fn_read_image p_read_img;
    LOAD(h, create_read, "png_create_read_struct");
    LOAD(h, create_info, "png_create_info_struct");
    LOAD(h, destroy, "png_destroy_read_struct");
    LOAD(h, set_error_fn, "png_set_error_fn");
    LOAD(h, set_read_fn, "png_set_read_fn");
    LOAD(h, read_info, "png_read_info");
    // getters share typedefs; load by explicit cast
    p_get_w = (fn_get_u32)dlsym(h, "png_get_image_width");
    p_get_h = (fn_get_u32)dlsym(h, "png_get_image_height");
    p_get_ct = (fn_get_int)dlsym(h, "png_get_color_type");
    p_get_bd = (fn_get_int)dlsym(h, "png_get_bit_depth");
    p_get_rb = (fn_get_rowbytes)dlsym(h, "png_get_rowbytes");
    p_strip16 = (fn_void_p)dlsym(h, "png_set_strip_16");
    p_packing = (fn_void_p)dlsym(h, "png_set_packing");
    p_expand = (fn_void_p)dlsym(h, "png_set_expand");
    p_pal2rgb = (fn_void_p)dlsym(h, "png_set_palette_to_rgb");
    p_trns2a = (fn_void_p)dlsym(h, "png_set_tRNS_to_alpha");
    p_gray2rgb = (fn_void_p)dlsym(h, "png_set_gray_to_rgb");
    p_upd = (fn_read_update)dlsym(h, "png_read_update_info");
    p_read_img = (fn_read_image)dlsym(h, "png_read_image");
    if (!p_get_w || !p_get_h || !p_get_ct || !p_get_bd || !p_get_rb ||
        !p_strip16 || !p_packing || !p_expand || !p_pal2rgb || !p_trns2a ||
        !p_gray2rgb || !p_upd || !p_read_img) {
        snprintf(out, sizeof(out), "%s: dlsym batch failed", label);
        goto done;
    }

    {
        pngtest_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.p = pngBuf;
        ctx.left = pngLen;
        g_ctx = &ctx;
        if (setjmp(ctx.jmp)) {
            snprintf(out, sizeof(out), "%s: libpng error: %s", label, ctx.err);
            g_ctx = NULL;
            goto done;
        }
        png_structp ps = p_create_read("1.6.51", NULL, NULL, NULL);
        if (!ps) { snprintf(out, sizeof(out), "%s: create_read failed", label); g_ctx = NULL; goto done; }
        png_infop pi = p_create_info(ps);
        if (!pi) { snprintf(out, sizeof(out), "%s: create_info failed", label); g_ctx = NULL; goto done; }
        p_set_error_fn(ps, NULL, pt_error, pt_warn);
        p_set_read_fn(ps, NULL, pt_read);
        p_read_info(ps, pi);
        png_uint_32 w = p_get_w(ps, pi), hh = p_get_h(ps, pi);
        int ct = p_get_ct(ps, pi), bd = p_get_bd(ps, pi);
        // Skia-like expansion transforms
        p_strip16(ps); p_packing(ps); p_expand(ps);
        p_pal2rgb(ps); p_trns2a(ps); p_gray2rgb(ps);
        p_upd(ps, pi);
        png_size_t rb = p_get_rb(ps, pi);

        // per-row mallocs with 32B head/tail canaries
        png_bytepp rows = malloc(hh * sizeof(png_bytep));
        unsigned char *bufs = NULL;
        if (rows) bufs = malloc(hh * (rb + 64));
        if (!rows || !bufs) {
            snprintf(out, sizeof(out), "%s: row alloc failed", label);
            free(rows); free(bufs); g_ctx = NULL; goto done;
        }
        for (png_uint_32 y = 0; y < hh; y++) {
            unsigned char *b = bufs + y * (rb + 64);
            memset(b, 0xAA, 32);
            memset(b + 32 + rb, 0xBB, 32);
            rows[y] = b + 32;
        }
        p_read_img(ps, rows);

        int badRows = 0, firstBad = -1;
        size_t maxOver = 0;
        int headBad = 0;
        for (png_uint_32 y = 0; y < hh; y++) {
            unsigned char *b = bufs + y * (rb + 64);
            for (int i = 0; i < 32; i++) if (b[i] != 0xAA) { headBad = 1; break; }
            size_t over = 0;
            for (int i = 0; i < 32; i++) if (b[32 + rb + i] != 0xBB) { over = 32 - i; break; }
            // find exact first clobbered byte from the end side
            if (over) {
                size_t first = 0;
                while (first < 32 && b[32 + rb + first] == 0xBB) first++;
                over = 32 - first;
                badRows++;
                if (firstBad < 0) firstBad = y;
                if (over > maxOver) maxOver = over;
            }
        }
        snprintf(tmp, sizeof(tmp),
                "%s: %ux%u ct=%d bd=%d rowbytes=%u rows=%u badRows=%d firstBad=%d maxOverrun=%zu headBad=%d %s",
                label, w, hh, ct, bd, (unsigned)rb, (unsigned)hh,
                badRows, firstBad, maxOver, headBad,
                (badRows > 0 ? "VULNERABLE PATH CONFIRMED" : "canaries intact"));
        strncpy(out, tmp, sizeof(out) - 1);
        LOGI("%s", out);
        png_structp ps2 = ps; png_infop pi2 = pi;
        p_destroy(&ps2, &pi2, NULL);
        free(rows); free(bufs);
        g_ctx = NULL;
    }

done:
    if (label) (*env)->ReleaseStringUTFChars(env, labelJ, label);
    free(pngBuf);
    return (*env)->NewStringUTF(env, out[0] ? out : "empty");
}
