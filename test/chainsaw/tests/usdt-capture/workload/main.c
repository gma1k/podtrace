/*
 * Minimal USDT-instrumented workload for podtrace e2e.
 *
 * Ships a known `.note.stapsdt` note set so the agent's USDT scanner has a
 * deterministic target:
 *   - provider "podtrace_test", name "hit"     — always-on probe (exercises A1)
 *   - provider "podtrace_test", name "guarded" — semaphore-guarded probe; only
 *     fires while a tracer has enabled the ref_ctr semaphore (exercises A2)
 *
 * Both probes carry one argument (the loop counter) so the same binary can
 * later validate argument decode (A3).
 */
#include <sys/sdt.h>
#include <unistd.h>

/*
 * Declare the semaphore for the "guarded" probe. systemtap's sys/sdt.h emits a
 * non-zero semaphore address into the note when a symbol named
 * <provider>_<name>_semaphore lives in the ".probes" section and is referenced
 * by DTRACE_PROBE. The kernel increments it on uprobe attach (ref_ctr_offset),
 * so the guard below only passes while podtrace is tracing.
 */
__extension__ unsigned short podtrace_test_guarded_semaphore
    __attribute__((section(".probes"), used));

int main(void) {
    unsigned long counter = 0;
    for (;;) {
        /* Always-on probe: fires every iteration once attached. */
        DTRACE_PROBE1(podtrace_test, hit, counter);

        /* Semaphore-guarded probe: fires only while enabled by a tracer. */
        if (podtrace_test_guarded_semaphore) {
            DTRACE_PROBE1(podtrace_test, guarded, counter);
        }

        counter++;
        usleep(200000); /* ~5 hits/sec — brisk but not floody */
    }
    return 0;
}
