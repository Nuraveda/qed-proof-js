import { parseArgs } from "node:util";
import { login, logout, claim, claimsList, receiptsGet, watch, verify, logHead } from "./commands.js";
import { defaultIo } from "./io.js";

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;

  switch (command) {
    case "login": {
      const { values } = parseArgs({
        args: rest,
        options: {
          "key-stdin": { type: "boolean" },
          "base-url": { type: "string" },
        },
      });
      return login({ keyStdin: values["key-stdin"] as boolean | undefined, baseUrl: values["base-url"] as string | undefined }, defaultIo);
    }
    case "logout":
      return logout(defaultIo);
    case "claim": {
      const [action, ...flagArgs] = rest;
      if (!action) {
        defaultIo.error("usage: qed claim <action> --target T [--param k=v ...] [--agent ID] [--id CLIENT_ID] [--wait] [--json]");
        return 1;
      }
      const { values } = parseArgs({
        args: flagArgs,
        options: {
          target: { type: "string" },
          param: { type: "string", multiple: true, default: [] },
          agent: { type: "string" },
          id: { type: "string" },
          wait: { type: "boolean" },
          json: { type: "boolean" },
        },
      });
      if (!values.target) {
        defaultIo.error("qed claim: --target is required");
        return 1;
      }
      return claim(
        {
          action,
          target: values.target as string,
          param: (values.param as string[]) ?? [],
          agent: values.agent as string | undefined,
          id: values.id as string | undefined,
          wait: values.wait as boolean | undefined,
          json: values.json as boolean | undefined,
        },
        defaultIo,
      );
    }
    case "claims": {
      const [sub, ...flagArgs] = rest;
      if (sub !== "list") {
        defaultIo.error("usage: qed claims list [--limit N] [--agent ID] [--action A] [--verdict V] [--state S] [--all] [--json]");
        return 1;
      }
      const { values } = parseArgs({
        args: flagArgs,
        options: {
          limit: { type: "string" },
          agent: { type: "string" },
          action: { type: "string" },
          verdict: { type: "string" },
          state: { type: "string" },
          all: { type: "boolean" },
          json: { type: "boolean" },
        },
      });
      return claimsList(
        {
          limit: values.limit !== undefined ? Number(values.limit) : undefined,
          agent: values.agent as string | undefined,
          action: values.action as string | undefined,
          verdict: values.verdict as string | undefined,
          state: values.state as string | undefined,
          all: values.all as boolean | undefined,
          json: values.json as boolean | undefined,
        },
        defaultIo,
      );
    }
    case "receipts": {
      const [sub, id, ...flagArgs] = rest;
      if (sub !== "get" || !id) {
        defaultIo.error("usage: qed receipts get <id> [--json]");
        return 1;
      }
      const { values } = parseArgs({ args: flagArgs, options: { json: { type: "boolean" } } });
      return receiptsGet({ id, json: values.json as boolean | undefined }, defaultIo);
    }
    case "watch": {
      const [claimId, ...flagArgs] = rest;
      if (!claimId) {
        defaultIo.error("usage: qed watch <claim-id> [--json]");
        return 1;
      }
      const { values } = parseArgs({ args: flagArgs, options: { json: { type: "boolean" } } });
      return watch({ claimId, json: values.json as boolean | undefined }, defaultIo);
    }
    case "verify": {
      const [file, ...flagArgs] = rest;
      if (!file) {
        defaultIo.error("usage: qed verify <file|https-url> [--keys file|url] [--rpc url] [--pipeline file] [--head file|url] [--consistency file ...] [--issuer url] [--nitro-root file (tests only)] [--json]");
        return 1;
      }
      const { values } = parseArgs({
        args: flagArgs,
        options: {
          "nitro-root": { type: "string" },
          keys: { type: "string" },
          rpc: { type: "string" },
          pipeline: { type: "string" },
          head: { type: "string" },
          consistency: { type: "string", multiple: true, default: [] },
          issuer: { type: "string" },
          json: { type: "boolean" },
        },
      });
      return verify(
        {
          file,
          keys: values.keys as string | undefined,
          rpc: values.rpc as string | undefined,
          pipeline: values.pipeline as string | undefined,
          head: values.head as string | undefined,
          consistency: (values.consistency as string[]) ?? [],
          issuer: values.issuer as string | undefined,
          nitroRoot: values["nitro-root"] as string | undefined,
          json: values.json as boolean | undefined,
        },
        defaultIo,
      );
    }
    case "log": {
      const [sub, ...flagArgs] = rest;
      if (sub !== "head") {
        defaultIo.error("usage: qed log head [--verify] [--keys file|url] [--json]");
        return 1;
      }
      const { values } = parseArgs({
        args: flagArgs,
        options: { verify: { type: "boolean" }, keys: { type: "string" }, json: { type: "boolean" } },
      });
      return logHead(
        { verify: values.verify as boolean | undefined, keys: values.keys as string | undefined, json: values.json as boolean | undefined },
        defaultIo,
      );
    }
    default:
      defaultIo.error("qed: commands are login, logout, claim, claims list, receipts get, watch, verify, log head");
      return command ? 1 : 0;
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((exc) => {
    defaultIo.error(exc instanceof Error ? exc.message : String(exc));
    process.exitCode = 1;
  });
