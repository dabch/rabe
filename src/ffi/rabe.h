#define FFI_LIB "librabe.so"

struct KpAbeContext;

struct KpAbeContext* kpabe_create();
void kpabe_destroy(struct KpAbeContext* ctx);
int32_t kpabe_encrypt(const void* pk, char* attributes, char* pt, int32_t pt_len, char** ct, int32_t *ct_len);


