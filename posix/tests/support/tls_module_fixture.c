/* Link real TLS templates; symbol offsets are checked independently with nm. */
__thread unsigned char initialized[7] = {VALUE, 2, 3, 4, 5, 6, 7};
__thread unsigned char zeroed[8195] __attribute__((aligned(ALIGNMENT)));
