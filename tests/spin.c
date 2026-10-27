#include <stdio.h>
#include <unistd.h>

int main(void) {
    puts("FATHOM_SPIN_READY");
    fflush(stdout);
    for (;;) {
        pause();
    }
}
