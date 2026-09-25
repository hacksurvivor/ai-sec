import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { runRedTeamSuite } from "./index.js";

describe("runRedTeamSuite", () => {
  it("runs prompt_injection_core suite", () => {
    const run = runRedTeamSuite({
      suite: "prompt_injection_core",
      targetModel: "test-model"
    });

    assert.equal(run.suite, "prompt_injection_core");
    assert.equal(run.status, "pass");
    assert.ok(run.totalCases >= 1);
    assert.equal(run.successfulAttacks, 0);
  });

  it("runs elder_plinius suite", () => {
    const run = runRedTeamSuite({
      suite: "elder_plinius",
      targetModel: "test-model"
    });

    assert.equal(run.suite, "elder_plinius");
    assert.equal(run.status, "pass");
    assert.ok(run.totalCases >= 1);
    assert.equal(run.successfulAttacks, 0);
  });
});
