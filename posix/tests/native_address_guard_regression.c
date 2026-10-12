/* Link native_address_wait_guarded.c with main=guarded_address_probe and
 * native_terminal_window.c with main=posix_regression_main. */
int guarded_address_probe(void);
int posix_regression_main(void);

int main(void) {
    int status = guarded_address_probe();
    return status ? status : posix_regression_main();
}
