package burp;

import java.util.Set;
import java.util.function.IntFunction;

/**
 * Pre-report gate that distinguishes a real desync from a time-correlated confound
 * (a rebooting / flaky backend). Runs N cycles of: attack run -> wait gapMs -> attack-free
 * control run. A run is "dirty" if it produced a non-boring victim status code != the
 * Phase-2 baseline code B.
 *
 * - Any dirty control -> DISCARD (early exit).
 * - 0 dirty controls and >= reproThreshold dirty attack runs -> VERIFIED.
 * - Otherwise -> UNREPLICABLE.
 */
public final class CorrelationCheck {

    public enum Verdict { VERIFIED, UNREPLICABLE, DISCARD }

    public record Result(Verdict verdict, int attackDirtyCycles, int cyclesRun) {}

    private final int cycles;
    private final long gapMs;
    private final int reproThreshold;

    public CorrelationCheck(int cycles, long gapMs, int reproThreshold) {
        this.cycles = cycles;
        this.gapMs = gapMs;
        this.reproThreshold = reproThreshold;
    }

    /** Production config: N=5 cycles, gap from settings, reproduction threshold 3. */
    public static CorrelationCheck defaults(long gapMs) {
        return new CorrelationCheck(5, gapMs, 3);
    }

    private static boolean dirty(Set<Integer> observedCodes, int baselineCode) {
        for (int code : observedCodes) {
            if (code != baselineCode) {
                return true;
            }
        }
        return false;
    }

    public Result run(int baselineCode,
                      IntFunction<Set<Integer>> attackRun,
                      IntFunction<Set<Integer>> controlRun) throws InterruptedException {
        int attackDirtyCycles = 0;
        for (int cycle = 1; cycle <= cycles; cycle++) {
            if (dirty(attackRun.apply(cycle), baselineCode)) {
                attackDirtyCycles++;
            }
            Thread.sleep(gapMs);
            if (dirty(controlRun.apply(cycle), baselineCode)) {
                return new Result(Verdict.DISCARD, attackDirtyCycles, cycle);
            }
        }
        Verdict verdict = attackDirtyCycles >= reproThreshold
            ? Verdict.VERIFIED : Verdict.UNREPLICABLE;
        return new Result(verdict, attackDirtyCycles, cycles);
    }
}
