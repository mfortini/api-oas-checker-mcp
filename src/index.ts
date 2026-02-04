#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ErrorCode,
    ListToolsRequestSchema,
    McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SPECTRAL_BIN = path.resolve(__dirname, "..", "node_modules", ".bin", "spectral");

const server = new Server(
    {
        name: "api-oas-checker",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

const STANDARD_RULESETS: Record<string, string> = {
    "spectral": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral.yml",
    "spectral-full": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral-full.yml",
    "spectral-generic": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral-generic.yml",
    "spectral-security": "https://github.com/italia/api-oas-checker-rules/releases/latest/download/spectral-security.yml",
};

const ValidateOpenApiSchema = z.object({
    openapi_path: z.string().optional(),
    openapi_content: z.string().optional(),
    filter_path: z.string().optional().describe("Filter results by JSON path (e.g. 'paths./users')"),
    line_start: z.number().optional().describe("Filter results starting from this line (1-indexed)"),
    line_end: z.number().optional().describe("Filter results up to this line (1-indexed)"),
    max_issues: z.number().default(20).describe("Cap the number of returned issues"),
    ruleset_path: z.string().optional().describe("URL or local path to a custom spectral ruleset file"),
    standard_ruleset: z.enum(["spectral", "spectral-full", "spectral-generic", "spectral-security"]).optional().describe("Use a standard ruleset from the Italian guidelines."),
    allowed_rules: z.array(z.string()).optional().describe("List of rule codes to verify. If omitted, all rules are checked."),
});

const ListRulesSchema = z.object({
    ruleset_path: z.string().optional().describe("URL or local path to a spectral ruleset file"),
    standard_ruleset: z.enum(["spectral", "spectral-full", "spectral-generic", "spectral-security"]).optional().describe("Use a standard ruleset from the Italian guidelines."),
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "validate_openapi",
                description: "Validate an OpenAPI specification using Italian PA guidelines (Spectral).",
                inputSchema: zodToJsonSchema(ValidateOpenApiSchema),
            },
            {
                name: "list_rules",
                description: "List available rules from a Spectral ruleset.",
                inputSchema: zodToJsonSchema(ListRulesSchema),
            },
        ],
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === "list_rules") {
        const args = ListRulesSchema.safeParse(request.params.arguments);
        if (!args.success) {
            throw new McpError(ErrorCode.InvalidParams, "Invalid arguments");
        }

        let rulesetUrl = STANDARD_RULESETS["spectral"];
        if (args.data.ruleset_path) {
            rulesetUrl = args.data.ruleset_path;
        } else if (args.data.standard_ruleset) {
            rulesetUrl = STANDARD_RULESETS[args.data.standard_ruleset];
        }

        let rulesContent = "";

        try {
            if (rulesetUrl.startsWith("http")) {
                const response = await fetch(rulesetUrl);
                if (!response.ok) {
                    throw new Error(`Failed to fetch ruleset: ${response.statusText}`);
                }
                rulesContent = await response.text();
            } else {
                rulesContent = await fs.promises.readFile(rulesetUrl, "utf-8");
            }

            const ruleset = yaml.load(rulesContent) as any;
            if (!ruleset || !ruleset.rules) {
                return {
                    content: [{ type: "text", text: "No rules found in the provided ruleset." }],
                };
            }

            const rules = Object.entries(ruleset.rules).map(([code, rule]: [string, any]) => {
                return {
                    code,
                    description: rule.description || rule.message || "No description",
                    severity: rule.severity || "unknown",
                };
            });

            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(rules, null, 2),
                    },
                ],
            };

        } catch (error: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error fetching or parsing ruleset: ${error.message}`,
                    },
                ],
                isError: true,
            };
        }
    }

    if (request.params.name !== "validate_openapi") {
        throw new McpError(ErrorCode.MethodNotFound, "Unknown tool");
    }

    const args = ValidateOpenApiSchema.safeParse(request.params.arguments);
    if (!args.success) {
        throw new McpError(ErrorCode.InvalidParams, "Invalid arguments");
    }

    const { openapi_path, openapi_content, filter_path, line_start, line_end, max_issues, ruleset_path, allowed_rules, standard_ruleset } = args.data;

    if (!openapi_path && !openapi_content) {
        throw new McpError(ErrorCode.InvalidParams, "Must provide either openapi_path or openapi_content");
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
            throw new Error("Unexpected state");
        }

        // Ruleset URL
        let rulesetUrl = STANDARD_RULESETS["spectral"];
        if (ruleset_path) {
            rulesetUrl = ruleset_path;
        } else if (standard_ruleset) {
            rulesetUrl = STANDARD_RULESETS[standard_ruleset];
        }

        // Fix for spectral-security and spectral-full which depend on checkSecurity.js
        // The release/download content expects functions/checkSecurity.js relative path, but it's not in the release.
        // We download the ruleset and the function locally to make it work.
        if (rulesetUrl === STANDARD_RULESETS["spectral-security"] || rulesetUrl === STANDARD_RULESETS["spectral-full"]) {
            debug(`Fix ruleset for ${standard_ruleset}`);
            const cacheDir = path.join(os.tmpdir(), "mcp-api-oas-checker-cache");
            if (!fs.existsSync(cacheDir)) {
                await fs.promises.mkdir(cacheDir, { recursive: true, mode: 0o700 });
            }
            if (!fs.existsSync(path.join(cacheDir, "functions"))) {
                await fs.promises.mkdir(path.join(cacheDir, "functions"), { recursive: true, mode: 0o700 });
            }

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
        } catch (e: any) {
            // Spectral returns exit code 1 if issues are found, but stdout still contains the JSON
            if (e.stdout) {
                stdout = e.stdout;
            } else {
                throw new Error(`Spectral failed: ${e.stderr || e.message}`);
            }
        }

        if (!stdout) {
            return {
                content: [{ type: "text", text: "No issues found or empty output." }],
            };
        }

        let issues: any[] = [];
        try {
            issues = JSON.parse(stdout);
        } catch (e) {
            return {
                content: [{ type: "text", text: `Failed to parse Spectral JSON output: ${stdout.slice(0, 200)}...` }],
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
        const cappedIssues = filteredIssues.slice(0, max_issues);

        // Formatting
        const header = `Found ${totalIssues} issues` +
            (totalIssues > max_issues ? ` (showing first ${max_issues})` : "") +
            `:`;

        const lines = cappedIssues.map((issue: any) => {
            const line = issue.range.start.line + 1;
            const severity = ["Error", "Warning", "Information", "Hint"][issue.severity] || "Unknown";
            return `Line ${line}: [${severity}] ${issue.message} (${issue.code})`;
        });

        const resultText = [header, ...lines].join("\n");

        return {
            content: [
                {
                    type: "text",
                    text: resultText,
                },
            ],
        };

    } catch (error: any) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error executing spectral: ${error.message}`,
                },
            ],
            isError: true,
        };
    } finally {
        if (cleanUpFile && filePathToLint) {
            try {
                await fs.promises.unlink(filePathToLint);
            } catch (e) {
                // ignore
            }
        }
    }
});

const transport = new StdioServerTransport();
await server.connect(transport);
