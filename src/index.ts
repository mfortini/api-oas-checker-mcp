#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer, IncomingMessage, ServerResponse } from "http";
import { randomUUID } from "crypto";
import { registerTools } from "./tools.js";

// --- Server initialization ---

function createAndConfigureServer(): McpServer {
    const server = new McpServer({
        name: "api-oas-checker",
        version: "1.0.0",
    });

    // Register all tools
    registerTools(server);

    return server;
}

// --- Main function with transport mode support ---

async function main() {
    console.error("[Startup] API OAS Checker MCP Server initializing...");
    console.error("[Startup] Node version:", process.version);
    console.error("[Startup] Working directory:", process.cwd());

    // Support both stdio (default) and HTTP/SSE modes
    const transportMode = process.env.MCP_TRANSPORT || 'stdio';
    console.error("[Startup] Transport mode:", transportMode);

    if (transportMode === 'sse' || transportMode === 'http') {
        // HTTP mode for Docker/remote access using StreamableHTTPServerTransport
        console.error("[Startup] Configuring Streamable HTTP server...");
        const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
        const HOST = process.env.HOST || '0.0.0.0';
        console.error(`[Startup] Will listen on ${HOST}:${PORT}`);

        // Session tracking: map session IDs to their transport + server
        const sessions = new Map<string, { server: McpServer; transport: StreamableHTTPServerTransport }>();

        /** Parse JSON body from an IncomingMessage */
        function parseBody(req: IncomingMessage): Promise<unknown> {
            return new Promise((resolve, reject) => {
                const chunks: Buffer[] = [];
                req.on('data', (chunk: Buffer) => chunks.push(chunk));
                req.on('end', () => {
                    const raw = Buffer.concat(chunks).toString();
                    if (!raw) { resolve(undefined); return; }
                    try { resolve(JSON.parse(raw)); }
                    catch (e) { reject(e); }
                });
                req.on('error', reject);
            });
        }

        const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
            const url = new URL(req.url || '/', `http://${req.headers.host}`);
            console.error(`[HTTP] ${req.method} ${url.pathname} from ${req.socket.remoteAddress}`);

            // Health check endpoint
            if (url.pathname === '/health') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ status: 'ok', service: 'api-oas-checker-mcp', sessions: sessions.size }));
                return;
            }

            // MCP endpoint – delegate everything to StreamableHTTPServerTransport
            if (url.pathname === '/mcp') {
                try {
                    // Check for existing session
                    const sessionId = req.headers['mcp-session-id'] as string | undefined;

                    if (sessionId && sessions.has(sessionId)) {
                        // Existing session: forward request to its transport
                        const session = sessions.get(sessionId)!;
                        const body = req.method === 'POST' ? await parseBody(req) : undefined;
                        console.error(`[MCP] Existing session ${sessionId}, method=${req.method}`);
                        await session.transport.handleRequest(req, res, body);
                        return;
                    }

                    if (req.method === 'POST') {
                        // New session: create server + transport, connect, then handle the initialize request
                        console.error("[MCP] New session initializing...");
                        const body = await parseBody(req);
                        const serverInstance = createAndConfigureServer();
                        const transport = new StreamableHTTPServerTransport({
                            sessionIdGenerator: () => randomUUID(),
                        });

                        // Clean up session when transport closes
                        transport.onclose = () => {
                            const sid = transport.sessionId;
                            if (sid) {
                                console.error(`[MCP] Session ${sid} closed, cleaning up`);
                                sessions.delete(sid);
                            }
                        };

                        // exactOptionalPropertyTypes requires onclose to be defined before connect
                        await serverInstance.connect(transport as Parameters<typeof serverInstance.connect>[0]);

                        // Handle the initialize request (this sets transport.sessionId)
                        await transport.handleRequest(req, res, body);

                        // Store session for future requests
                        const sid = transport.sessionId;
                        if (sid) {
                            sessions.set(sid, { server: serverInstance, transport });
                            console.error(`[MCP] Session ${sid} created (active sessions: ${sessions.size})`);
                        }
                        return;
                    }

                    // GET or DELETE without valid session
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        jsonrpc: '2.0',
                        error: { code: -32000, message: 'No valid session. Send an initialize POST first.' },
                        id: null,
                    }));
                } catch (error) {
                    console.error("[MCP] Request error:", error);
                    if (!res.headersSent) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: String(error) }));
                    }
                }
                return;
            }

            // 404 for other paths
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Not found', hint: 'MCP endpoint is at /mcp' }));
        });

        httpServer.listen(PORT, HOST, () => {
            console.error(`[Startup] ✓ API OAS Checker MCP Server running on http://${HOST}:${PORT}`);
            console.error(`[Startup] ✓ MCP endpoint: http://${HOST}:${PORT}/mcp`);
            console.error(`[Startup] ✓ Health check: http://${HOST}:${PORT}/health`);
            console.error("[Startup] Server ready to accept connections");
        });

        httpServer.on('error', (error) => {
            console.error("[Startup] HTTP Server error:", error);
        });
    } else {
        // Stdio mode for local process spawning (default)
        console.error("[Startup] Initializing stdio transport...");
        console.error("[Startup] Creating and configuring server instance...");
        const server = createAndConfigureServer();
        const transport = new StdioServerTransport();
        console.error("[Startup] Connecting server to transport...");
        await server.connect(transport);
        console.error("[Startup] API OAS Checker MCP Server running on stdio");
        console.error("[Startup] Server ready to accept requests");
    }
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
