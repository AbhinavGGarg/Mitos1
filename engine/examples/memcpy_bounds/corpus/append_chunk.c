/* copied into netd/ from the same upstream, heavier drift:
 * uint8_t buffers, descriptive names, an extra fast-path branch. */
int append_chunk(uint8_t *dstbuf, size_t dstbuf_len, const uint8_t *chunk, size_t chunk_len) {
    /* fast path: nothing to do */
    if (chunk_len == 0)
        return 0;
    memcpy(dstbuf, chunk, chunk_len);
    return (int)chunk_len;
}
