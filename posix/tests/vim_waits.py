#!/usr/bin/env python3
"""Compile Vim's real inchar_loop with deterministic clock/wait callbacks."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]

SUPPORT = r'''
#include <assert.h>
#include <stddef.h>
typedef unsigned char char_u;
typedef long elapsed_T;
#define FALSE 0
#define TRUE 1
#define ELAPSED_INIT(v) ((v) = 0)
#define ELAPSED_FUNC(v) ((void)(v), elapsed_sample())
static long p_ut = 4000;
static long samples[4], waits[4];
static unsigned sample_count, sample_index, wait_count, blocked;
static int infinite;
static long elapsed_sample(void) {
    unsigned index = sample_index++;
    return samples[index < sample_count ? index : sample_count - 1];
}
static int trigger_cursorhold(void) { return 0; }
static int typebuf_changed(int count) { (void)count; return 0; }
static void add_to_input_buf(char_u *bytes, int count) { (void)bytes; (void)count; }
static void before_blocking(void) { ++blocked; }
static int input_available(void) { return 1; }
static int read_from_input_buf(char_u *bytes, long count) {
    assert(count > 0); bytes[0] = 'X'; return 1;
}
#define CSI 0x9b
#define KS_EXTRA 0xfd
#define KE_CURSORHOLD 0x60
#define K_SPECIAL 0x80
static int wait_callback(long duration, int *interrupted, int ignore) {
    (void)interrupted; (void)ignore;
    assert(wait_count < 4);
    waits[wait_count++] = duration;
    return infinite && duration == -1;
}
'''

CASES = r'''
static void reset(long first, long later, int indefinitely) {
    samples[0] = first; samples[1] = later; sample_count = 2;
    sample_index = wait_count = blocked = 0; infinite = indefinitely;
}
int main(void) {
    char_u byte;
    const long requested[] = {0, 0, 1, 100};
    const long elapsed[] = {0, 2, 2, 101};
    for (unsigned i = 0; i < 4; ++i) {
        reset(elapsed[i], elapsed[i], 0);
        assert(inchar_loop(&byte, 1, requested[i], 0, wait_callback, NULL) == 0);
        assert(wait_count == 1 && waits[0] == 0 && blocked == 0);
    }
    reset(25, 101, 0);
    assert(inchar_loop(&byte, 1, 100, 0, wait_callback, NULL) == 0);
    assert(wait_count == 1 && waits[0] == 75 && blocked == 0);
    reset(2, 5000, 1);
    assert(inchar_loop(&byte, 1, -1, 0, wait_callback, NULL) == 1 && byte == 'X');
    assert(wait_count == 2 && waits[0] == 3998 && waits[1] == -1 && blocked == 1);
    reset(5000, 5000, 1);
    assert(inchar_loop(&byte, 1, -1, 0, wait_callback, NULL) == 1 && byte == 'X');
    assert(wait_count == 2 && waits[0] == 0 && waits[1] == -1 && blocked == 1);
}
'''


def main(source):
    text = source.read_text()
    start = text.index("\n    int\ninchar_loop(")
    end = text.index("\n}\n", start) + 3
    with tempfile.TemporaryDirectory(prefix="vim-waits-", dir=ROOT / "out/checks/tmp") as name:
        directory = Path(name)
        test, binary = directory / "waits.c", directory / "waits"
        test.write_text(SUPPORT + text[start:end] + CASES)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, cwd=directory)
    print("vim-waits: PASS real input loop: expired polls, remaining deadlines and intentional indefinite wait")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="patched Vim src/ui.c")
    main(parser.parse_args().source)
