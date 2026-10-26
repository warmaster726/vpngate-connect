#include <dlfcn.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>

typedef bool (*protect_fd_cb_t)(void *ctx, int fd);
typedef int (*establish_tun_cb_t)(
    void *ctx,
    const char *assigned_ip,
    const char *peer_ip,
    const char *dns1,
    const char *dns2,
    int mtu
);

typedef char *(*fn_l2tp_start_t)(
    const char *server_ip,
    const char *dns_csv,
    int timeout_secs,
    void *cb_ctx,
    protect_fd_cb_t protect_cb,
    establish_tun_cb_t establish_cb
);
typedef void (*fn_l2tp_stop_t)(void);
typedef void (*fn_free_string_t)(char *ptr);

typedef struct {
    JNIEnv *env;
    jobject vpn_service;
    jmethodID mid_protect;
    jmethodID mid_establish;
} jni_l2tp_ctx_t;

static void *g_rust_handle = NULL;
static fn_l2tp_start_t g_fn_start = NULL;
static fn_l2tp_stop_t g_fn_stop = NULL;
static fn_free_string_t g_fn_free = NULL;

static bool ensure_rust_symbols(void) {
    if (g_fn_start != NULL && g_fn_stop != NULL && g_fn_free != NULL) {
        return true;
    }
    if (g_rust_handle == NULL) {
        g_rust_handle = dlopen("libvpngate_bridge.so", RTLD_NOW | RTLD_GLOBAL);
        if (g_rust_handle == NULL) {
            return false;
        }
    }
    g_fn_start = (fn_l2tp_start_t)dlsym(g_rust_handle, "vpngate_l2tp_start_with_callbacks");
    g_fn_stop = (fn_l2tp_stop_t)dlsym(g_rust_handle, "vpngate_l2tp_stop");
    g_fn_free = (fn_free_string_t)dlsym(g_rust_handle, "vpngate_free_string");
    return (g_fn_start != NULL && g_fn_stop != NULL && g_fn_free != NULL);
}

static bool jni_protect_fd_trampoline(void *raw_ctx, int fd) {
    jni_l2tp_ctx_t *ctx = (jni_l2tp_ctx_t *)raw_ctx;
    if (ctx == NULL || ctx->env == NULL) {
        return false;
    }
    jboolean ok = (*ctx->env)->CallBooleanMethod(
        ctx->env,
        ctx->vpn_service,
        ctx->mid_protect,
        (jint)fd
    );
    if ((*ctx->env)->ExceptionCheck(ctx->env)) {
        (*ctx->env)->ExceptionClear(ctx->env);
        return false;
    }
    return ok == JNI_TRUE;
}

static int jni_establish_tun_trampoline(
    void *raw_ctx,
    const char *assigned_ip,
    const char *peer_ip,
    const char *dns1,
    const char *dns2,
    int mtu
) {
    jni_l2tp_ctx_t *ctx = (jni_l2tp_ctx_t *)raw_ctx;
    if (ctx == NULL || ctx->env == NULL) {
        return -2;
    }
    JNIEnv *env = ctx->env;
    jstring j_assigned = (*env)->NewStringUTF(env, assigned_ip ? assigned_ip : "");
    jstring j_peer = (*env)->NewStringUTF(env, peer_ip ? peer_ip : "");
    jstring j_dns1 = (*env)->NewStringUTF(env, dns1 ? dns1 : "1.1.1.1");
    jstring j_dns2 = (*env)->NewStringUTF(env, dns2 ? dns2 : "1.0.0.1");

    jint fd = (*env)->CallIntMethod(
        env,
        ctx->vpn_service,
        ctx->mid_establish,
        j_assigned,
        j_peer,
        j_dns1,
        j_dns2,
        (jint)mtu
    );

    (*env)->DeleteLocalRef(env, j_assigned);
    (*env)->DeleteLocalRef(env, j_peer);
    (*env)->DeleteLocalRef(env, j_dns1);
    (*env)->DeleteLocalRef(env, j_dns2);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return -2;
    }
    return (int)fd;
}

JNIEXPORT jstring JNICALL
Java_org_vpngate_connect_VpnGateVpnService_nativeStartL2tp(
    JNIEnv *env,
    jobject thiz,
    jstring j_server_ip,
    jstring j_dns_csv,
    jint timeout_secs
) {
    if (!ensure_rust_symbols()) {
        return (*env)->NewStringUTF(
            env,
            "{\"ok\":false,\"error\":\"Failed loading libvpngate_bridge.so symbols\"}"
        );
    }

    jclass cls = (*env)->GetObjectClass(env, thiz);
    jmethodID mid_protect = (*env)->GetMethodID(env, cls, "protectSocket", "(I)Z");
    jmethodID mid_establish = (*env)->GetMethodID(
        env,
        cls,
        "establishL2tpTun",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)I"
    );
    (*env)->DeleteLocalRef(env, cls);

    if (mid_protect == NULL || mid_establish == NULL) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return (*env)->NewStringUTF(
            env,
            "{\"ok\":false,\"error\":\"Missing VpnGateVpnService callback methods\"}"
        );
    }

    const char *c_ip = (*env)->GetStringUTFChars(env, j_server_ip, NULL);
    const char *c_dns = (*env)->GetStringUTFChars(env, j_dns_csv, NULL);

    jni_l2tp_ctx_t ctx = {
        .env = env,
        .vpn_service = thiz,
        .mid_protect = mid_protect,
        .mid_establish = mid_establish,
    };

    char *rust_json = g_fn_start(
        c_ip,
        c_dns,
        (int)timeout_secs,
        &ctx,
        jni_protect_fd_trampoline,
        jni_establish_tun_trampoline
    );

    (*env)->ReleaseStringUTFChars(env, j_server_ip, c_ip);
    (*env)->ReleaseStringUTFChars(env, j_dns_csv, c_dns);

    if (rust_json == NULL) {
        return (*env)->NewStringUTF(
            env,
            "{\"ok\":false,\"error\":\"Null response from vpngate_l2tp_start_with_callbacks\"}"
        );
    }

    jstring out = (*env)->NewStringUTF(env, rust_json);
    g_fn_free(rust_json);
    return out;
}

JNIEXPORT void JNICALL
Java_org_vpngate_connect_VpnGateVpnService_nativeStopL2tp(
    JNIEnv *env,
    jobject thiz
) {
    (void)env;
    (void)thiz;
    if (ensure_rust_symbols()) {
        g_fn_stop();
    }
}
