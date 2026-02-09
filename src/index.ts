#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import yaml from "js-yaml";
import { fileURLToPath } from "url";

const execFilePromise = promisify(execFile);

const DEBUG = !!process.env.MCP_DEBUG;
function debug(msg: string) {
    if (DEBUG) console.error(`[DEBUG] ${msg}`);
}

const CHARACTER_LIMIT = 12000;
const MAX_GUIDANCE_CHARS = 220;
const MAX_LINE_SAMPLES_PER_RULE = 3;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SPECTRAL_BIN = path.resolve(__dirname, "..", "node_modules", ".bin", "spectral");

const STANDARD_RULESETS: Record<string, string> = {
    "spectral": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral.yml",
    "spectral-full": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral-full.yml",
    "spectral-generic": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral-generic.yml",
    "spectral-security": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral-security.yml",
};

const STANDARD_RULESET_NAMES = ["spectral", "spectral-full", "spectral-generic", "spectral-security"] as const;

// --- TypeScript interfaces ---

interface SpectralIssue {
    code: string;
    message: string;
    description?: string;
    path: string[];
    severity: number;
    range: {
        start: { line: number; character: number };
        end: { line: number; character: number };
    };
}

interface ParsedRule {
    code: string;
    description: string;
    severity: string;
}

interface RulesetData {
    rules?: Record<string, { description?: string; message?: string; severity?: string }>;
}

// --- Zod schemas ---

const ValidateOpenApiSchema = z.object({
    openapi_path: z.string().optional()
        .describe("Absolute path to a local OpenAPI file (YAML or JSON). Provide either this or openapi_content."),
    openapi_content: z.string().optional()
        .describe("Raw OpenAPI specification content (YAML or JSON string). Provide either this or openapi_path."),
    filter_path: z.string().optional()
        .describe("Filter results by JSON path substring (e.g. 'paths./users', 'info.contact'). Only issues whose path contains this string are returned."),
    line_start: z.number().optional()
        .describe("Filter results starting from this line number (1-indexed, inclusive)."),
    line_end: z.number().optional()
        .describe("Filter results up to this line number (1-indexed, inclusive)."),
    max_issues: z.number().default(20)
        .describe("Maximum number of issues to return. Default: 20."),
    ruleset_path: z.string().optional()
        .describe("URL or absolute local path to a custom Spectral ruleset file. Overrides standard_ruleset."),
    standard_ruleset: z.enum(STANDARD_RULESET_NAMES).optional()
        .describe("Standard Italian PA ruleset to use: 'spectral' (default, core rules), 'spectral-full' (all rules incl. security), 'spectral-generic' (generic API rules), 'spectral-security' (security-focused rules)."),
    allowed_rules: z.array(z.string()).optional()
        .describe("Whitelist of rule codes to check (e.g. ['has-contact', 'use-semver']). If omitted, all rules are checked."),
}).strict();

const ListRulesSchema = z.object({
    ruleset_path: z.string().optional()
        .describe("URL or absolute local path to a Spectral ruleset file. Overrides standard_ruleset."),
    standard_ruleset: z.enum(STANDARD_RULESET_NAMES).optional()
        .describe("Standard Italian PA ruleset: 'spectral' (default), 'spectral-full', 'spectral-generic', 'spectral-security'."),
}).strict();

// --- Shared helpers ---

function resolveRulesetUrl(rulesetPath?: string, standardRuleset?: string): string {
    if (rulesetPath) return rulesetPath;
    if (standardRuleset) return STANDARD_RULESETS[standardRuleset];
    return STANDARD_RULESETS["spectral"];
}

async function fetchRulesetContent(rulesetUrl: string): Promise<string> {
    if (rulesetUrl.startsWith("http")) {
        const response = await fetch(rulesetUrl);
        if (!response.ok) {
            throw new Error(`Failed to fetch ruleset: ${response.statusText}`);
        }
        return response.text();
    }
    return fs.promises.readFile(rulesetUrl, "utf-8");
}

function parseRuleset(content: string): RulesetData {
    return yaml.load(content) as RulesetData;
}

function extractRuleDescriptions(ruleset: RulesetData): Record<string, string> {
    const descriptions: Record<string, string> = {};
    if (ruleset?.rules) {
        for (const [code, rule] of Object.entries(ruleset.rules)) {
            const desc = rule.description || rule.message || "";
            if (desc) descriptions[code] = desc;
        }
    }
    return descriptions;
}

function normalizeGuidanceText(text?: string): string {
    if (!text) return "";
    return text.replace(/\s+/g, " ").trim();
}

function compactGuidance(text: string): string {
    if (text.length <= MAX_GUIDANCE_CHARS) return text;
    return `${text.slice(0, MAX_GUIDANCE_CHARS - 3)}...`;
}

function truncateIfNeeded(text: string): string {
    if (text.length > CHARACTER_LIMIT) {
        return text.slice(0, CHARACTER_LIMIT) + "\n\n[Output truncated. Use filters (filter_path, line_start/line_end, allowed_rules) or reduce max_issues to get focused results.]";
    }
    return text;
}

// --- Server ---

const server = new McpServer({
    name: "api-oas-checker",
    version: "1.0.0",
});

// --- Tool: list_rules ---

server.registerTool(
    "list_rules",
    {
        title: "List Spectral Rules",
        description: `List available validation rules from an Italian PA Spectral ruleset.

Returns a JSON array of rule objects, each with code, description, and severity.

Args:
  - standard_ruleset (string, optional): One of 'spectral', 'spectral-full', 'spectral-generic', 'spectral-security'. Default: 'spectral'.
  - ruleset_path (string, optional): URL or local path to a custom ruleset. Overrides standard_ruleset.

Returns:
  JSON array of objects:
  [
    {
      "code": "has-contact",
      "description": "API MUST reference a contact...",
      "severity": "error"
    }
  ]

Examples:
  - List core Italian PA rules: { "standard_ruleset": "spectral" }
  - List security rules: { "standard_ruleset": "spectral-security" }
  - Use a custom ruleset: { "ruleset_path": "https://example.com/my-rules.yml" }

Error Handling:
  - Returns an error if the ruleset URL is unreachable or the YAML is invalid.`,
        inputSchema: ListRulesSchema,
        annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: true,
        },
    },
    async ({ ruleset_path, standard_ruleset }) => {
        try {
            const rulesetUrl = resolveRulesetUrl(ruleset_path, standard_ruleset);
            const rulesContent = await fetchRulesetContent(rulesetUrl);
            const ruleset = parseRuleset(rulesContent);

            if (!ruleset?.rules) {
                return {
                    content: [{ type: "text", text: "No rules found in the provided ruleset." }],
                };
            }

            const rules: ParsedRule[] = Object.entries(ruleset.rules).map(([code, rule]) => ({
                code,
                description: rule.description || rule.message || "No description",
                severity: rule.severity || "unknown",
            }));

            return {
                content: [{ type: "text", text: JSON.stringify(rules, null, 2) }],
            };
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            return {
                content: [{ type: "text", text: `Error fetching or parsing ruleset: ${message}` }],
                isError: true,
            };
        }
    }
);

// --- Tool: validate_openapi ---

server.registerTool(
    "validate_openapi",
    {
        title: "Validate OpenAPI Specification",
        description: `Validate an OpenAPI specification (OAS3) against Italian Public Administration guidelines using Spectral.

Runs the official Italian PA linting rules on the provided OpenAPI document and returns a structured report of issues found, grouped by rule with fix guidance.

Args:
  - openapi_path (string, optional): Absolute path to a local OpenAPI file (YAML/JSON). Mutually exclusive with openapi_content.
  - openapi_content (string, optional): Raw OpenAPI content as a string. Mutually exclusive with openapi_path.
  - standard_ruleset (string, optional): Ruleset to use: 'spectral' (default, core), 'spectral-full' (all+security), 'spectral-generic' (generic API), 'spectral-security' (security).
  - ruleset_path (string, optional): URL or local path to a custom Spectral ruleset. Overrides standard_ruleset.
  - allowed_rules (string[], optional): Only check these rule codes (e.g. ['has-contact', 'use-semver']). If omitted, all rules.
  - filter_path (string, optional): Only show issues whose JSON path contains this string (e.g. 'paths./users').
  - line_start (number, optional): Only show issues on or after this line (1-indexed).
  - line_end (number, optional): Only show issues on or before this line (1-indexed).
  - max_issues (number, optional): Cap the number of issues returned. Default: 20.

Returns:
  A text report with two sections:
  1. "Rules violated (with fix guidance)" — each violated rule listed once with severity and description.
  2. "Locations" — compact list of line numbers and rule codes.

  Example output:
  Found 3 issues:

  ## Rules violated (with fix guidance):
  - has-contact [Error]: API MUST reference a contact...
  - use-semver [Error]: The API version field should follow semver.

  ## Locations:
  L2: has-contact
  L2: use-semver
  L5: has-contact

Examples:
  - Validate a local file: { "openapi_path": "/home/user/api.yaml" }
  - Validate pasted content: { "openapi_content": "openapi: 3.0.3\\ninfo:..." }
  - Check only security rules: { "openapi_path": "/home/user/api.yaml", "standard_ruleset": "spectral-security" }
  - Focus on a specific path: { "openapi_path": "/home/user/api.yaml", "filter_path": "paths./users" }

Error Handling:
  - Returns error if neither openapi_path nor openapi_content is provided.
  - Returns error if Spectral binary is not found or fails to execute.
  - Returns error if the ruleset cannot be fetched or parsed.`,
        inputSchema: ValidateOpenApiSchema,
        annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: true,
        },
    },
    async ({ openapi_path, openapi_content, filter_path, line_start, line_end, max_issues, ruleset_path, allowed_rules, standard_ruleset }) => {
        if (!openapi_path && !openapi_content) {
            return {
                content: [{ type: "text", text: "Error: Must provide either openapi_path or openapi_content." }],
                isError: true,
            };
        }

        let filePathToLint = openapi_path;
        let cleanUpFile = false;

        try {
            if (openapi_content) {
                const tempDir = os.tmpdir();
                const tempFile = path.join(tempDir, `temp_openapi_${crypto.randomUUID()}.yaml`);
                await fs.promises.writeFile(tempFile, openapi_content);
                filePathToLint = tempFile;
                cleanUpFile = true;
            } else if (!filePathToLint) {
                throw new Error("Unexpected state: no file path and no content.");
            }

            let rulesetUrl = resolveRulesetUrl(ruleset_path, standard_ruleset);

            // Fix for spectral-security and spectral-full which depend on checkSecurity.js
            if (rulesetUrl === STANDARD_RULESETS["spectral-security"] || rulesetUrl === STANDARD_RULESETS["spectral-full"]) {
                debug(`Fix ruleset for ${standard_ruleset}`);
                const cacheDir = path.join(os.tmpdir(), "mcp-api-oas-checker-cache");
                await fs.promises.mkdir(path.join(cacheDir, "functions"), { recursive: true, mode: 0o700 });

                const ruleFilename = path.basename(rulesetUrl);
                const localRulesetPath = path.join(cacheDir, ruleFilename);
                const localFunctionPath = path.join(cacheDir, "functions", "checkSecurity.js");

                if (!fs.existsSync(localRulesetPath)) {
                    debug(`Downloading ruleset from ${rulesetUrl} to ${localRulesetPath}`);
                    const rulesetResp = await fetch(rulesetUrl);
                    if (!rulesetResp.ok) throw new Error(`Failed to download ruleset: ${rulesetResp.statusText}`);
                    const rulesetContent = await rulesetResp.text();
                    await fs.promises.writeFile(localRulesetPath, rulesetContent);
                } else {
                    debug(`Using cached ruleset at ${localRulesetPath}`);
                }

                if (!fs.existsSync(localFunctionPath)) {
                    debug(`Downloading checkSecurity.js to ${localFunctionPath}`);
                    const functionUrl = "https://raw.githubusercontent.com/italia/api-oas-checker-rules/refs/heads/main/security/functions/checkSecurity.js";
                    const funcResp = await fetch(functionUrl);
                    if (!funcResp.ok) throw new Error(`Failed to download checkSecurity.js: ${funcResp.statusText}`);
                    const funcContent = await funcResp.text();
                    await fs.promises.writeFile(localFunctionPath, funcContent);
                } else {
                    debug(`Using cached checkSecurity.js`);
                }

                rulesetUrl = localRulesetPath;
                debug(`Ruleset fixed at ${rulesetUrl}`);
            }

            // Run Spectral via execFile (no shell interpolation — prevents command injection)
            debug(`Running Spectral on ${filePathToLint} with ruleset ${rulesetUrl}`);
            const spectralArgs = ["lint", filePathToLint!, "-r", rulesetUrl, "-f", "json", "--quiet"];

            let stdout = "";
            try {
                const result = await execFilePromise(SPECTRAL_BIN, spectralArgs, { maxBuffer: 1024 * 1024 * 10 });
                stdout = result.stdout;
            } catch (e: unknown) {
                // Spectral returns exit code 1 if issues are found, but stdout still contains the JSON
                const execError = e as { stdout?: string; stderr?: string; message?: string };
                if (execError.stdout) {
                    stdout = execError.stdout;
                } else {
                    throw new Error(`Spectral failed: ${execError.stderr || execError.message}`);
                }
            }

            if (!stdout) {
                return {
                    content: [{ type: "text", text: "No issues found. The OpenAPI specification passes all checked rules." }],
                };
            }

            let issues: SpectralIssue[];
            try {
                issues = JSON.parse(stdout);
            } catch (_e) {
                return {
                    content: [{ type: "text", text: `Failed to parse Spectral JSON output: ${stdout.slice(0, 200)}...` }],
                    isError: true,
                };
            }

            // Filtering
            let filteredIssues = issues;

            if (allowed_rules && allowed_rules.length > 0) {
                filteredIssues = filteredIssues.filter(issue => allowed_rules.includes(issue.code));
            }

            if (filter_path) {
                filteredIssues = filteredIssues.filter(issue => {
                    const pathStr = issue.path.join(".");
                    return pathStr.includes(filter_path);
                });
            }

            if (line_start !== undefined) {
                filteredIssues = filteredIssues.filter(issue => issue.range.start.line + 1 >= line_start);
            }

            if (line_end !== undefined) {
                filteredIssues = filteredIssues.filter(issue => issue.range.start.line + 1 <= line_end);
            }

            const totalIssues = filteredIssues.length;
            if (totalIssues === 0) {
                return {
                    content: [{ type: "text", text: "No issues found for the selected filters." }],
                };
            }

            const cappedIssues = filteredIssues.slice(0, max_issues);

            // Load ruleset to get rule descriptions (for fix guidance)
            let ruleDescriptions: Record<string, string> = {};
            try {
                const rulesContent = await fetchRulesetContent(rulesetUrl);
                const ruleset = parseRuleset(rulesContent);
                ruleDescriptions = extractRuleDescriptions(ruleset);
            } catch (_e) {
                debug(`Could not load rule descriptions: ${_e}`);
            }

            // Compact summary per rule: one guidance + occurrence count + sample lines
            const violatedRules = new Map<string, { severity: string; guidance: string; count: number; lines: Set<number> }>();
            for (const issue of cappedIssues) {
                const code = issue.code;
                const issueDescription = normalizeGuidanceText(issue.description);
                const ruleDescription = normalizeGuidanceText(ruleDescriptions[code]);
                const issueMessage = normalizeGuidanceText(issue.message);
                const guidance = issueDescription || ruleDescription || issueMessage || "No guidance available";
                const line = issue.range.start.line + 1;

                if (!violatedRules.has(code)) {
                    const severity = ["Error", "Warning", "Information", "Hint"][issue.severity] || "Unknown";
                    violatedRules.set(code, { severity, guidance: compactGuidance(guidance), count: 1, lines: new Set([line]) });
                } else {
                    const ruleInfo = violatedRules.get(code)!;
                    ruleInfo.count++;
                    if (ruleInfo.lines.size < MAX_LINE_SAMPLES_PER_RULE) {
                        ruleInfo.lines.add(line);
                    }
                }
            }

            const header = `${totalIssues} issues` +
                (totalIssues > max_issues ? ` (sampled first ${max_issues})` : "");

            const rulesSection = Array.from(violatedRules.entries())
                .map(([code, info]) => {
                    const lines = Array.from(info.lines).sort((a, b) => a - b);
                    const linesLabel = lines.length > 0 ? ` @L${lines.join(",L")}` : "";
                    return `- ${code} [${info.severity}] x${info.count}${linesLabel}: ${info.guidance}`;
                })
                .join("\n");

            const resultText = [
                header,
                rulesSection,
            ].join("\n");

            return {
                content: [{ type: "text", text: truncateIfNeeded(resultText) }],
            };

        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : String(error);
            return {
                content: [{ type: "text", text: `Error executing spectral: ${message}` }],
                isError: true,
            };
        } finally {
            if (cleanUpFile && filePathToLint) {
                try {
                    await fs.promises.unlink(filePathToLint);
                } catch (_e) {
                    // ignore
                }
            }
        }
    }
);

// --- Start server ---

const transport = new StdioServerTransport();
await server.connect(transport);
