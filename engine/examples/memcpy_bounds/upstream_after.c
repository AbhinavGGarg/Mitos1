/* librecord/store.c  —  fixed version (the upstream security fix)
 * Adds the missing bounds check before the copy.
 */
int store_record(char *buf, size_t buf_size, const char *data, size_t data_len) {
    if (data_len > buf_size)
        return -1;
    memcpy(buf, data, data_len);
    return 0;
}
