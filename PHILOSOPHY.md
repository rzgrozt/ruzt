## 1. Project Philosophy & North Star

Use these principles to guide architectural decisions and resolve disagreements about first principles.

**Ruzt's North Star:**

1. **Memory safety is non-negotiable.** Outside a tightly-audited `unsafe` core (paging, MMIO, atomics, context switches), every line compiles in safe Rust. The unsafe core is documented, justified, and re-reviewed quarterly.
2. **Least privilege, always.** No process gets a permission it did not explicitly request. The default capability set on a new process is *empty*. This is the privacy story.
3. **The user is the principal, not the application.** Apps don't "own" their data; the user grants apps capabilities to specific data. (This is the same insight Qubes OS and Android's permission model began with, but enforced from the kernel up.)
4. **Telemetry-zero by default.** Not "opt-out". *Off.* No analytics endpoint exists in the base system. If a future feature requires telemetry, it requires an explicit RFC and a user opt-in flow.
5. **Reproducible from source.** Anyone with the source tree, the toolchain version, and a clean machine must produce a byte-identical image. This is the supply-chain story.
6. **Aesthetic as a feature, not a finishing touch.** Visual coherence is engineered from day one — the boot splash, the TTY font, the panic screen, the installer, and the desktop must feel like one product, not a kit of parts.
7. **Discoverable internals.** A motivated newcomer should be able to read the source of any subsystem and understand it within an afternoon. This is partly a code-style choice and partly an architectural one (small modules, clear ownership).
8. **Robust under failure.** Every subsystem assumes its peers may crash. Recovery is a first-class operation, not an afterthought. Crash-only design (Section 17) is a project rule, not an aspiration.
9. **Boring where it matters, bold where it pays off.** Use battle-tested ideas (paging, ELF, MMIO, Wayland) for the substrate. Save novelty for the interfaces (capability model, package format, capability-aware protocol extensions) where it changes the user experience.

**Anti-goals — say "no" loudly:**

- Ruzt is **not** a Linux clone. POSIX is a compatibility *shim*, not a goal.
- Ruzt is **not** a server-first OS. The first-class persona is a privacy-conscious end-user laptop, with a path to mobile.
- Ruzt is **not** trying to be the fastest. Microkernels pay a per-syscall cost. We accept that.
- Ruzt **does not** ship a JavaScript runtime in the base image. (No Electron-shaped escape hatches.)

Print this on the wiki. Refuse PRs that contradict it.
