import fs from "node:fs";
import path from "node:path";
const contractRoot = path.resolve(
  process.env.CONTRACTS_DIR ?? "../algaguard-contracts",
);
const required = [
  "schemas/common/event-envelope-v1.schema.json",
  "schemas/websocket/realtime-envelope-v1.schema.json",
  "asyncapi/algaguard-mqtt-v1.yaml",
  "asyncapi/algaguard-websocket-v1.yaml",
  "schemas/common/device-identity-v1.schema.json",
  "schemas/internal/device-context-v1.schema.json",
];
const missing = required.filter(
  (file) => !fs.existsSync(path.join(contractRoot, file)),
);
if (missing.length > 0)
  throw new Error(`Missing algaguard-contracts files: ${missing.join(", ")}`);
process.stdout.write(
  `Validated ${required.length} required files from algaguard-contracts.\n`,
);

// gRPC .proto files are loaded at container runtime (@grpc/proto-loader
// reads real files from disk, unlike the JSON schemas above which are only
// checked at CI time), so the Docker image can't rely on a sibling
// algaguard-contracts checkout -- this service vendors its own copy under
// proto/. This check keeps that copy from silently drifting from the
// source of truth.
const vendoredProtos = [
  "common.proto",
  "access_service.proto",
  "device_service.proto",
];
// Compare without line endings: a Windows checkout (core.autocrlf) gives the
// vendored copy CRLF while the contracts copy may stay LF.
const readNormalized = (file: string) =>
  fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
const protoMismatches = vendoredProtos.filter((file) => {
  const vendored = path.resolve("proto", file);
  const source = path.join(contractRoot, "proto", file);
  if (!fs.existsSync(source)) return true;
  return readNormalized(vendored) !== readNormalized(source);
});
if (protoMismatches.length > 0)
  throw new Error(
    `Vendored proto/ files differ from algaguard-contracts: ${protoMismatches.join(", ")}`,
  );
process.stdout.write(
  `Validated ${vendoredProtos.length} vendored proto files match algaguard-contracts.\n`,
);
