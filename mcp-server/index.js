#!/usr/bin/env node
/**
 * Zentric Protocol — MCP server
 * Exposes the /v1/analyze API as a single `analyze_prompt` tool
 * for any MCP-compatible agent (Claude Desktop, Cursor, etc.).
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const VERSION = '0.1.0';
const ENDPOINT = 'https://api.zentricprotocol.com/v1/analyze';
const TOOL_NAME = 'analyze_prompt';
const TOOL_DESCRIPTION =
  'Analyze a prompt for injection attacks and PII before sending it to an LLM. ' +
  'Returns a verdict (CLEARED/BLOCKED), matched injection signatures, detected PII entities, ' +
  'SHA-256 hash, and a GDPR Art.30-compliant audit report.';

const TOOL_INPUT_SCHEMA = {
  type: 'object',
  properties: {
    input: {
      type: 'string',
      description: 'The prompt or text to analyze.',
    },
    modules: {
      type: 'array',
      items: { type: 'string', enum: ['integrity', 'privacy'] },
      description: 'Which Zentric modules to run. Defaults to both.',
      default: ['integrity', 'privacy'],
    },
  },
  required: ['input'],
  additionalProperties: false,
};

function requireApiKey() {
  const key = process.env.ZENTRIC_API_KEY;
  if (!key || !key.trim()) {
    throw new Error(
      'ZENTRIC_API_KEY environment variable is not set. ' +
        'Get a free key (2,000 requests / month, no credit card) at https://zentricprotocol.com',
    );
  }
  return key.trim();
}

async function analyzePrompt({ input, modules }) {
  const apiKey = requireApiKey();
  const mods = Array.isArray(modules) && modules.length > 0 ? modules : ['integrity', 'privacy'];

  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': `zentric-protocol-mcp/${VERSION}`,
    },
    body: JSON.stringify({ input, modules: mods, options: { language: 'auto' } }),
  });

  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }

  if (!res.ok) {
    return {
      ok: false,
      status: res.status,
      error: body?.error || res.statusText || 'request_failed',
      message: body?.message || `Zentric Protocol API returned status ${res.status}`,
    };
  }
  return body;
}

const server = new Server(
  { name: 'zentric-protocol-mcp', version: VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: TOOL_NAME,
      description: TOOL_DESCRIPTION,
      inputSchema: TOOL_INPUT_SCHEMA,
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== TOOL_NAME) {
    return {
      isError: true,
      content: [
        { type: 'text', text: `Unknown tool: ${request.params.name}` },
      ],
    };
  }
  try {
    const args = request.params.arguments || {};
    if (typeof args.input !== 'string' || !args.input.trim()) {
      return {
        isError: true,
        content: [
          { type: 'text', text: 'input must be a non-empty string' },
        ],
      };
    }
    const result = await analyzePrompt({ input: args.input, modules: args.modules });
    return {
      content: [
        { type: 'text', text: JSON.stringify(result, null, 2) },
      ],
    };
  } catch (err) {
    return {
      isError: true,
      content: [
        { type: 'text', text: `Zentric MCP error: ${err?.message || String(err)}` },
      ],
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
