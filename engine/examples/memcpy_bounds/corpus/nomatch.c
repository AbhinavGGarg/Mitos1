/* unrelated code — no copy call, no lineage. Must be ignored. */
int log_line(const char *msg) {
    printf("%s\n", msg);
    return 0;
}
