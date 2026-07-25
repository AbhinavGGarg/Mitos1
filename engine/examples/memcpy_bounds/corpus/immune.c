/* also descended from librecord, but this fork already added its own
 * bounds check — Patch DNA must recognise it as immune and skip it. */
int store_thing(char *b, size_t bsz, const char *d, size_t dl) {
    if (dl > bsz)
        return -1;
    memcpy(b, d, dl);
    return 0;
}
