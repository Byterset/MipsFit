// Record a CPU execution trace for MipsFit.
// Usage: ares-test trace-scenario.js <rom.z64> <game.elf> <out.xtrace> [frames] [start marker]
//
// Waits for the ROM to reach a steady state (an ISViewer marker, or a fixed
// number of VI ticks), then records `frames` ticks of execution and writes
// <out.xtrace> plus <out.xtrace>.json. Needs an ares built with
// ARES_ENABLE_DEBUG_TOOLS (preset linux-headless-debug).
import {capture} from "./capture.js";

const [rom, elf, path, frames = "120", marker] = ares.args;
if (!path) throw new Error("usage: trace-scenario.js <rom> <elf> <out.xtrace> [frames] [marker]");
const count = Number(frames);
if (!(count > 0)) throw new Error("frames must be positive");

capture({
  rom, elf, scenario: "gameplay",
  trace: {path, maxBytes: 2 ** 31},
  setup: () => {
    if (marker) {
      if (!ares.waitLog(marker, 60)) throw new Error("marker never appeared: " + marker);
    } else {
      ares.waitFrames(120);  // skip boot and the first loading frames
    }
  },
}, () => ares.waitFrames(count));
