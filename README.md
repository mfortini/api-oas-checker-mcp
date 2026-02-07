# MCP API OAS Checker

![Release](https://img.shields.io/github/v/release/mfortini/api-oas-checker-mcp?style=flat-square)
![License](https://img.shields.io/github/license/mfortini/api-oas-checker-mcp?style=flat-square)
![Issues](https://img.shields.io/github/issues/mfortini/api-oas-checker-mcp?style=flat-square)

A Model Context Protocol (MCP) server that validates OpenAPI specifications (OAS3) using the official [Italian Public Administration Guidelines](https://github.com/italia/api-oas-checker-rules).

It wraps the [api-oas-checker](https://github.com/italia/api-oas-checker-rules) ruleset (Spectral) to provide validation directly within your LLM environment (like Claude Desktop).

## Features

- **Validate OpenAPI Files**: Check local OpenAPI files against Italian PA rules.
- **Validate Content**: Paste OpenAPI content directly for validation.
- **Multiple Rulesets**: Choose from 4 standard Italian PA rulesets (`spectral`, `spectral-full`, `spectral-generic`, `spectral-security`) or use a custom one.
- **List Rules**: Inspect the available rules in any ruleset.
- **Smart Filtering**:
  - Filter by Line Numbers (`line_start`, `line_end`)
  - Filter by JSON Path (`filter_path`, e.g., `paths./users`)
  - Filter by Rule Codes (`allowed_rules`)
- **Token Efficient**: Summarized output design to save context window tokens.

## Installation

### Option 1: Install directly from GitHub (Recommended)

You can run the server directly using `npx` without cloning the repository manually:

```bash
npx -y github:mfortini/api-oas-checker-mcp
```

Or install it globally via `npm`:

```bash
npm install -g git+https://github.com/mfortini/api-oas-checker-mcp.git
```

Then you can run `api-oas-checker-mcp` directly.

Or add it to your configuration (see Configuration section).

### Option 2: Build from Source

```bash
git clone https://github.com/mfortini/api-oas-checker-mcp.git
cd api-oas-checker-mcp
npm install
```

The `prepare` script automatically compiles TypeScript during `npm install`.

**Verify Build**:
```bash
node build/index.js
```
(It should hang waiting for MCP input, which is normal. Press `Ctrl+C` to exit.)

## Configuration
/
### Claude Desktop

Add the server to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "api-oas-checker": {
      "command": "npx",
      "args": [
        "-y",
        "github:mfortini/api-oas-checker-mcp"
      ]
    }
  }
}
```

### From Local Build (Development)

If you built it locally:

```json
{
  "mcpServers": {
    "api-oas-checker": {
      "command": "node",
      "args": [
        "/absolute/path/to/api-oas-checker-mcp/build/index.js"
      ]
    }
  }
}
```

### Global Install

If you installed it globally:

```json
{
  "mcpServers": {
    "api-oas-checker": {
      "command": "api-oas-checker-mcp",
      "args": []
    }
  }
}
```

## Usage

### Tools

#### `validate_openapi`
Validates an OpenAPI document.

**Arguments:**
- `openapi_path` (string, optional): Absolute path to the file.
- `openapi_content` (string, optional): Raw string content of the OpenAPI file.
- `standard_ruleset` (string, optional): One of `spectral`, `spectral-full`, `spectral-generic`, `spectral-security`. Default: `spectral`.
- `ruleset_path` (string, optional): URL or local path to a custom Spectral ruleset file.
- `allowed_rules` (string[], optional): List of rule codes to check. If omitted, all rules are checked.
- `filter_path` (string, optional): Filter issues containing this string in their path (e.g., `info.version`).
- `line_start` (number, optional): Show issues starting from this line.
- `line_end` (number, optional): Show issues ending at this line.
- `max_issues` (number, optional): Limit the number of reported issues (Default: 20).

**Example Prompt:**
> "Check the file /home/user/my-api.yaml for errors, focusing on the '/users' path."

#### `list_rules`
Lists the available rules from a Spectral ruleset.

**Arguments:**
- `standard_ruleset` (string, optional): One of `spectral`, `spectral-full`, `spectral-generic`, `spectral-security`. Default: `spectral`.
- `ruleset_path` (string, optional): URL or local path to a custom Spectral ruleset file.

## Development

- `npm run build`: Compile TypeScript to JavaScript.
- `npm start`: Run the server (stdio).

## Contributing

Contributions are welcome! Please feel free to open a Pull Request.

## License

This project is licensed under the MIT License.
