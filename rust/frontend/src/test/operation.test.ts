import { describe, it, expect } from "vitest";
import { isVisibleOp, operationLabel, setActiveOperation } from "../stores/operation";

describe("operation store", () => {
  describe("isVisibleOp", () => {
    it("returns true for regular commands", () => {
      expect(isVisibleOp("get_ca_info")).toBe(true);
      expect(isVisibleOp("create_cert")).toBe(true);
    });

    it("returns false for hidden commands", () => {
      expect(isVisibleOp("acquire_lock")).toBe(false);
      expect(isVisibleOp("release_lock")).toBe(false);
      expect(isVisibleOp("check_for_updates")).toBe(false);
    });
  });

  describe("operationLabel", () => {
    it("returns null when no operation is active", () => {
      setActiveOperation(null);
      expect(operationLabel()).toBeNull();
    });

    it("returns the human-readable label for known commands", () => {
      setActiveOperation("connect");
      expect(operationLabel()).toBe("Connecting to vault\u2026");

      setActiveOperation("create_cert");
      expect(operationLabel()).toBe("Creating certificate\u2026");
    });

    it("falls back to the raw command name for unknown commands", () => {
      setActiveOperation("unknown_command");
      expect(operationLabel()).toBe("unknown_command");
    });
  });
});
