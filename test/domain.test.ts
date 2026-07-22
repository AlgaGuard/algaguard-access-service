import test from "node:test";
import assert from "node:assert/strict";
import { AccessStore } from "../src/domain.js";
test("organization owner is authorized and unrelated subject is denied", () => {
  const store = new AccessStore();
  const organization = store.createOrganization("Lab", "owner");
  assert.equal(store.authorize("owner", organization.id), true);
  assert.equal(store.authorize("other", organization.id), false);
});
test("current-user subscription is scoped to authenticated subject", () => {
  assert.equal(
    new AccessStore().authorizeSubscription("subject", "current-user"),
    true,
  );
});
