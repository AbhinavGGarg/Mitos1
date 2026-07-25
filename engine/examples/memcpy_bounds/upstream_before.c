/* librecord/store.c  —  vulnerable version (pre-fix)
 * CWE-120: copies data_len bytes into buf without checking buf_size.
 */
int store_record(char *buf, size_t buf_size, const char *data, size_t data_len) {
    memcpy(buf, data, data_len);
    return 0;
}
