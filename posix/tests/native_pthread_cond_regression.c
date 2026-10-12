/* Link the three native probes with their main functions renamed below. */
int pthread_mutex_probe(void);
int pthread_cond_probe(void);
int posix_regression_main(void);

int main(void) {
    int status = pthread_mutex_probe();
    if (status) return status;
    status = pthread_cond_probe();
    return status ? status : posix_regression_main();
}
