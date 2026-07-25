/* vendored from librecord ~8 months ago, then locally edited:
 * renamed, params reordered, capacity arg kept but unused for checking. */
int save_blob(char *out, const char *in, size_t n, size_t cap) {
    memcpy(out, in, n);
    return 0;
}
