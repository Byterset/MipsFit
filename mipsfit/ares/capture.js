// ares-test / QuickJS-NG ES module.
// Boots a ROM, records a CPU execution trace over a workload, and writes the
// sidecar that `mipsfit analyze --trace` reads to confirm the capture
// belongs to the ELF being analyzed. Needs an ares built with
// ARES_ENABLE_DEBUG_TOOLS (that is what provides ares.cpuTraceStart).

export function capture(config, workload) {
  const {rom, elf, scenario, trace} = config;
  if (!rom || !elf || !scenario || !trace || !trace.path) {
    throw new Error("capture needs rom, the ELF that ROM was built from, a scenario name and trace.path");
  }
  if (typeof ares.cpuTraceStart !== "function") {
    throw new Error("this ares build has no cpuTraceStart; configure it with ARES_ENABLE_DEBUG_TOOLS");
  }
  // Identify the build here rather than making the caller hash the ELF: the
  // sidecar below is what lets analyze refuse a capture from a different build.
  const elf_sha256 = ares.fileSha256(elf);
  ares.setRenderer(config.renderer || "angrylion");
  ares.setHomebrew(true);
  // The interpreter fetches every instruction through the modelled cache, so a
  // trace meant for exact replay is captured with the recompiler switched off.
  if (trace.interpreter !== false && typeof ares.setRecompiler === "function") {
    ares.setRecompiler(false);
  }
  ares.loadRom(rom); // Cold boot, so the capture always starts from the same state.
  ares.resume();
  try {
    if (config.setup) config.setup();
    ares.cpuTraceStart(trace.path, {maxBytes: trace.maxBytes || 0});
    workload();
    const recorded = ares.cpuTraceStop();
    if (!recorded.frames) throw new Error("the trace covers no frame; record across at least one VI tick");
    if (recorded.truncated) console.log("MIPSFIT_NOTE trace hit maxBytes; only its beginning is usable");
    // Attest which build produced the capture. analyze refuses a trace whose
    // ELF hash does not match, so a stale capture can never be scored silently.
    ares.writeFile(trace.path + ".json", JSON.stringify({elf_sha256, scenario}) + "\n");
    const result = {
      version: 1, elf_sha256, scenario, path: trace.path,
      frames: recorded.frames, instructions: recorded.instructions,
      icache_misses: recorded.fills, bytes: recorded.bytes, truncated: recorded.truncated,
    };
    console.log("MIPSFIT_RESULT " + JSON.stringify(result));
    return result;
  } finally {
    ares.closeRom();
  }
}

// Convenience for deterministic setup. Frame counts here mean VI ticks, not
// completed game frames. Workload completion should use a game marker/counter.
export function replay(actions) {
  for (const action of actions) {
    const p = () => ares.controller(action.port || 1);
    switch (action.op) {
      case "wait": ares.wait(action.seconds); break;
      case "waitFrames": ares.waitFrames(action.frames); break;
      case "hold": p().hold(action.button); break;
      case "release": p().release(action.button); break;
      case "stick": p().stick(action.x, action.y); break;
      case "clear": p().clear(); break;
      case "waitLog":
        if (!ares.waitLog(action.marker, action.timeoutSeconds || 30)) {
          throw new Error("Timed out waiting for " + action.marker);
        }
        break;
      default: throw new Error("Unknown replay operation: " + action.op);
    }
  }
}
