# Security Audit: paoloanzn/free-code

**Repository:** https://github.com/paoloanzn/free-code  
**Audit Date:** 2026-04-01  
**Auditor:** Automated security scan  
**Repository Description:** "The free build of Claude Code. All telemetry removed, security-prompt guardrails stripped, all experimental features enabled."

---

## Executive Summary

The repository `paoloanzn/free-code` is a **reconstructed copy of Anthropic's Claude Code CLI** (version 2.1.87) with modifications including telemetry removal, security guardrail stripping, Codex/OpenAI API integration, and all experimental features force-enabled. The audit identified **2 critical**, **3 high**, and **3 medium** severity findings.

**The primary risks to users are:**
1. Authentication through a stolen/extracted third-party OAuth client ID for OpenAI
2. All conversation data being routed through unofficial ChatGPT API endpoints when using Codex mode
3. No supply chain integrity (pipe-to-bash install with no signatures or checksums)
4. Implicit trust in an unknown maintainer distributing modified security-sensitive software

---

## Findings

### CRITICAL-01: Stolen OAuth Client Credentials for OpenAI Authentication

**File:** `src/constants/codex-oauth.ts`  
**Severity:** CRITICAL  

The repository uses an OAuth client ID (`app_EMoamEEZ73f0CkXaXp7hrann`) that the source code comments admit was **"extracted from the @mariozechner/pi-ai package used by the openclaw project"**. This means:

- Users authenticate with OpenAI using a **client ID they do not own or control**
- The registered OAuth application owner could potentially **revoke access, monitor usage, or rotate credentials** at any time
- This violates OpenAI's Terms of Service regarding OAuth client usage
- The OAuth redirect URI is hardcoded to `http://localhost:1455/auth/callback`

**Relevant constants:**
```
Client ID: app_EMoamEEZ73f0CkXaXp7hrann
Authorize URL: https://auth.openai.com/oauth/authorize
Token URL: https://auth.openai.com/oauth/token
```

**Risk:** Users who authenticate through this flow are entrusting their OpenAI account access to a third-party OAuth application registration they have no visibility into.

---

### CRITICAL-02: API Request Interception and Rerouting via Codex Fetch Adapter

**Files:** `src/services/api/codex-fetch-adapter.ts`, `src/services/api/client.ts`  
**Severity:** CRITICAL  

The repository implements a **fetch interceptor** that hijacks all Anthropic API requests and reroutes them to ChatGPT's backend:

**Injection mechanism:**
1. `src/services/api/client.ts` imports `createCodexFetch` from the adapter
2. When `isCodexSubscriber()` returns true, a custom `fetch` function replaces the Anthropic SDK's HTTP layer
3. Any request URL containing `/v1/messages` is intercepted
4. The request body is translated from Anthropic format to OpenAI Responses API format
5. The request is sent to `https://chatgpt.com/backend-api/codex/responses`
6. The streaming response is translated back to Anthropic SSE format

**What gets sent to ChatGPT's servers:**
- All user prompts and conversation history
- All system prompts (including CLAUDE.md contents and project context)
- All tool definitions and tool results (file contents, bash outputs, etc.)
- Model mapping: Claude Opus -> `gpt-5.1-codex-max`, Sonnet -> `gpt-5.2-codex`, Haiku -> `gpt-5.1-codex-mini`

**Key code from `client.ts`:**
```typescript
if (isCodexSubscriber()) {
  const codexTokens = getCodexOAuthTokens()
  if (codexTokens?.accessToken) {
    const codexFetch = createCodexFetch(codexTokens.accessToken)
    const clientConfig = {
      apiKey: 'codex-placeholder', // SDK requires a key but adapter handles auth
      ...ARGS,
      fetch: codexFetch as unknown as typeof globalThis.fetch,
    }
    return new Anthropic(clientConfig)
  }
}
```

**Risk:** All user code, project files, and conversations are sent to an **unofficial ChatGPT API endpoint** (`chatgpt.com/backend-api/codex/responses`) using stolen OAuth credentials. The endpoint `backend-api` is ChatGPT's internal web API, not a public developer API.

---

### HIGH-01: Pipe-to-Bash Installation with No Integrity Verification

**File:** `install.sh`  
**Severity:** HIGH  

Users are instructed to install via:
```bash
curl -fsSL https://raw.githubusercontent.com/paoloanzn/free-code/main/install.sh | bash
```

The install script:
1. **Runs a nested pipe-to-bash** to install Bun: `curl -fsSL https://bun.sh/install | bash`
2. **Clones from `main` with no pinned commit** (`git clone --depth 1`) - the repo owner can push malicious code at any time
3. **Falls back to unrestricted `bun install`** if `--frozen-lockfile` fails, allowing resolution to compromised dependency versions
4. **No checksums, signatures, or hash verification** of any kind

**Risk:** A single commit push to `main` could inject arbitrary code that runs on all new installations. The nested Bun install pipe adds a second remote code execution vector.

---

### HIGH-02: Unauthorized Redistribution of Anthropic Proprietary Software

**Severity:** HIGH  

The `package.json` names the project `claude-code-source-snapshot` at version `2.1.87`. The README states the source was obtained from a "source map exposure" of the Claude Code npm package. The code has been modified to:

- Strip all telemetry (analytics stubs return void)
- Remove security-prompt guardrails
- Enable all 37+ experimental features
- Add unauthorized OpenAI Codex API integration
- Remove Anthropic's feedback and issue reporting channels

**Risk:** Users are running a modified version of security-sensitive software from an untrusted source. Any bugs, vulnerabilities, or intentional backdoors in the modifications have no oversight from Anthropic.

---

### HIGH-03: Hidden "openclaw/" Directory Referenced but Git-Ignored

**Files:** `.gitignore`, `src/constants/codex-oauth.ts`  
**Severity:** HIGH  

The `.gitignore` explicitly excludes an `openclaw/` directory. The `codex-oauth.ts` file references "the openclaw project" as the source of the stolen OAuth credentials. This directory likely contains additional tooling or code that:

- Is used during development but deliberately hidden from the public repo
- May contain the original credential extraction tools
- Could contain additional API proxies, token harvesters, or other utilities

**Risk:** The existence of a deliberately hidden directory that is referenced as the source of stolen credentials indicates the developer has tooling they do not want publicly visible.

---

### MEDIUM-01: All Experimental Features Force-Enabled

**File:** `scripts/build.ts`  
**Severity:** MEDIUM  

The build script (`--feature-set=dev-full`) enables 37+ experimental features including:

| Feature | Risk |
|---------|------|
| `AGENT_TRIGGERS_REMOTE` | Remote agent trigger execution |
| `BRIDGE_MODE` | Remote control / bridge sessions |
| `CCR_REMOTE_SETUP` / `CCR_AUTO_CONNECT` | Remote code execution setup |
| `NATIVE_CLIENT_ATTESTATION` | Client attestation bypass |
| `DUMP_SYSTEM_PROMPT` | System prompt extraction |
| `BYPASS_PERMISSIONS_MODE` | Permission bypass (implied by UI component) |

These features are gated by Anthropic for security and stability reasons. Enabling them all in an untrusted build increases the attack surface.

---

### MEDIUM-02: JWT Decoding Without Signature Verification

**File:** `src/bridge/jwtUtils.ts`  
**Severity:** MEDIUM  

The `decodeJwtPayload()` function decodes JWT tokens without verifying signatures. While this is used only for extracting expiry times (not for auth decisions), in the context of an already-compromised trust model, it means token claims are trusted without verification.

---

### MEDIUM-03: Credential Storage on Disk in Remote Environments

**File:** `src/utils/authFileDescriptor.ts`  
**Severity:** MEDIUM  

In CCR (Claude Code Remote) environments, OAuth tokens and API keys are written to well-known paths:
- `/home/claude/.claude/remote/.oauth_token`
- `/home/claude/.claude/remote/.api_key`
- `/home/claude/.claude/remote/.session_ingress_token`

While file permissions are set to `0o600`, any same-user process can read these tokens. In a modified build with experimental features enabled, the expanded attack surface increases the risk of token exposure.

---

## What Was NOT Found (Positive Findings)

1. **No obfuscated or encoded malicious payloads** in the build script, CLI entrypoint, or source files
2. **Telemetry appears genuinely removed** - `src/services/analytics/index.ts` contains empty stub functions
3. **No evidence of redirected telemetry** to a third-party endpoint
4. **OAuth flows use standard PKCE patterns** - user passwords are never captured by the CLI
5. **No reverse shells, backdoors, or obvious data exfiltration code** beyond the Codex adapter
6. **The Anthropic API key is not sent to OpenAI** - when Codex mode is active, a dummy `'codex-placeholder'` key is used

---

## Architecture of the Attack Surface

```
User runs free-code
        |
        v
  Is Codex subscriber?
       / \
     No   Yes
      |     |
      v     v
  Normal    createCodexFetch() intercepts fetch
  Anthropic     |
  API flow      v
            Translates Anthropic request body
                |
                v
            Sends to https://chatgpt.com/backend-api/codex/responses
            with stolen OAuth credentials (app_EMoamEEZ73f0CkXaXp7hrann)
                |
                v
            Translates response back to Anthropic format
                |
                v
            CLI displays response as if from Claude
```

---

## Recommendations

1. **Do not install or use this tool.** It uses stolen OAuth credentials and routes data through unofficial API endpoints.
2. **If you have already authenticated:** Revoke your OpenAI OAuth tokens immediately at https://platform.openai.com/settings
3. **If you used an Anthropic API key:** Rotate the key immediately at https://console.anthropic.com
4. **Report the repository** to GitHub for Terms of Service violations (unauthorized redistribution, stolen OAuth credentials)
5. **Report to OpenAI** that client ID `app_EMoamEEZ73f0CkXaXp7hrann` is being used without authorization

---

## Files Analyzed

| Category | Files Examined |
|----------|---------------|
| Build & Install | `install.sh`, `scripts/build.ts`, `package.json`, `.gitignore` |
| Entrypoints | `src/entrypoints/cli.tsx`, `src/main.tsx`, `src/setup.ts` |
| API Layer | `src/services/api/client.ts`, `src/services/api/codex-fetch-adapter.ts`, `src/utils/codex-fetch-adapter.ts`, `src/utils/api.ts`, `src/utils/http.ts`, `src/utils/apiPreconnect.ts` |
| Auth & OAuth | `src/utils/auth.ts`, `src/utils/authPortable.ts`, `src/utils/authFileDescriptor.ts`, `src/services/oauth/index.ts`, `src/services/oauth/client.ts`, `src/services/oauth/codex-client.ts`, `src/cli/handlers/auth.ts`, `src/commands/login/login.tsx` |
| Constants | `src/constants/codex-oauth.ts`, `src/constants/oauth.ts` |
| Telemetry | `src/services/analytics/index.ts`, `src/services/diagnosticTracking.ts`, `src/services/internalLogging.ts` |
| Bridge & Remote | `src/bridge/workSecret.ts`, `src/bridge/jwtUtils.ts`, `src/bridge/trustedDevice.ts`, `src/upstreamproxy/relay.ts`, `src/upstreamproxy/upstreamproxy.ts` |
| Core Logic | `src/QueryEngine.ts`, `src/query.ts`, `src/utils/config.ts`, `src/utils/hooks.ts`, `src/utils/env.ts`, `src/utils/billing.ts`, `src/utils/model/model.ts` |
| Documentation | `README.md`, `CLAUDE.md`, `FEATURES.md`, `changes.md`, `env.d.ts` |
