
import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { URL, URLSearchParams } from 'url';

const RESPONSE_SCHEME = 'http-client-response';

class ResponseContentProvider implements vscode.TextDocumentContentProvider {
    private _onDidChange = new vscode.EventEmitter<vscode.Uri>();
    readonly onDidChange = this._onDidChange.event;
    private contentMap = new Map<string, string>();

    provideTextDocumentContent(uri: vscode.Uri): string {
        return this.contentMap.get(uri.toString()) || '';
    }

    update(uri: vscode.Uri, content: string) {
        this.contentMap.set(uri.toString(), content);
        this._onDidChange.fire(uri);
    }
}

const responseProvider = new ResponseContentProvider();
let outputChannel: vscode.OutputChannel;

export interface ResponseData {
    statusCode: number;
    statusMessage: string;
    headers: Record<string, string | string[]>;
    body: string;
}

export interface Dependency {
    name: string;
    args: Record<string, string>;
    alias?: string;
}

export interface Assertion {
    target: string;
    op: '==' | '!=' | 'contains' | '!contains';
    value: string;
}

export interface RequestBlock {
    name?: string;
    requires: Dependency[];
    text: string;
    startLine: number;
    endLine: number;
    expectStatus?: number;
    assertions?: Assertion[];
    noFollow?: boolean;
}

interface FileConfig {
    envName?: string;
    sessionFile?: string;
    oauth2CacheFile?: string;
}

// ---------------------------------------------------------------------------
// OAuth2
// ---------------------------------------------------------------------------

interface OAuth2Params {
    grant: string;
    tokenUrl: string;
    authUrl?: string;
    deviceUrl?: string;
    clientId: string;
    clientSecret?: string;
    scope?: string;
    redirectPort?: string;
}

interface OAuth2CacheEntry {
    access_token: string;
    expires_at: number; // unix seconds, 0 = no expiry
}

class OAuth2Cache {
    private entries: Map<string, OAuth2CacheEntry> = new Map();
    private file?: string;

    constructor(file?: string) {
        this.file = file;
        if (file && fs.existsSync(file)) {
            try {
                const data = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, OAuth2CacheEntry>;
                for (const [k, v] of Object.entries(data)) { this.entries.set(k, v); }
            } catch { /* ignore */ }
        }
    }

    get(key: string): string | undefined {
        const e = this.entries.get(key);
        if (!e) { return undefined; }
        if (e.expires_at !== 0 && Date.now() / 1000 >= e.expires_at) {
            this.entries.delete(key);
            return undefined;
        }
        return e.access_token;
    }

    set(key: string, token: string, ttlSeconds: number) {
        const expiresAt = ttlSeconds > 0 ? Math.floor(Date.now() / 1000) + ttlSeconds - 30 : 0;
        this.entries.set(key, { access_token: token, expires_at: expiresAt });
        this.save();
    }

    private save() {
        if (!this.file) { return; }
        const obj: Record<string, OAuth2CacheEntry> = {};
        for (const [k, v] of this.entries) { obj[k] = v; }
        try { fs.writeFileSync(this.file, JSON.stringify(obj, null, 2)); } catch { /* ignore */ }
    }
}

const oauth2DirectiveRegexes: Record<string, RegExp> = {
    grant:          /^\s*@oauth2-grant\s*=\s*(.+?)\s*$/,
    tokenUrl:       /^\s*@oauth2-token-url\s*=\s*(.+?)\s*$/,
    authUrl:        /^\s*@oauth2-auth-url\s*=\s*(.+?)\s*$/,
    deviceUrl:      /^\s*@oauth2-device-url\s*=\s*(.+?)\s*$/,
    clientId:       /^\s*@oauth2-client-id\s*=\s*(.+?)\s*$/,
    clientSecret:   /^\s*@oauth2-client-secret\s*=\s*(.+?)\s*$/,
    scope:          /^\s*@oauth2-scope\s*=\s*(.+?)\s*$/,
    redirectPort:   /^\s*@oauth2-redirect-port\s*=\s*(.+?)\s*$/,
};

function parseOAuth2Params(lines: string[]): OAuth2Params | undefined {
    const p: Partial<OAuth2Params> = {};
    for (const line of lines) {
        for (const [key, re] of Object.entries(oauth2DirectiveRegexes)) {
            const m = line.match(re);
            if (m) { (p as any)[key] = m[1]; }
        }
    }
    if (!p.grant) { return undefined; }
    if (!p.redirectPort) { p.redirectPort = '9876'; }
    return p as OAuth2Params;
}

function oauth2CacheKey(p: OAuth2Params): string {
    return `${p.grant}::${p.tokenUrl}::${p.clientId}::${p.scope ?? ''}`;
}

async function postToken(tokenUrl: string, params: Record<string, string>): Promise<{ token: string; expiresIn: number }> {
    const body = new URLSearchParams(params).toString();
    return new Promise((resolve, reject) => {
        const parsed = new URL(tokenUrl);
        const lib = parsed.protocol === 'https:' ? https : http;
        const req = lib.request({
            method: 'POST',
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
        }, (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
                try {
                    const data = JSON.parse(Buffer.concat(chunks).toString());
                    if (data.error) { return reject(new Error(`oauth2 error "${data.error}": ${data.error_description || ''}`)); }
                    if (!data.access_token) { return reject(new Error('oauth2: empty access_token')); }
                    resolve({ token: data.access_token, expiresIn: data.expires_in ?? 0 });
                } catch (e) { reject(e); }
            });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

async function acquireOAuth2Token(p: OAuth2Params, cache: OAuth2Cache): Promise<string> {
    const key = oauth2CacheKey(p);
    const cached = cache.get(key);
    if (cached) { return cached; }

    let token: string;
    let expiresIn: number;

    switch (p.grant) {
        case 'client_credentials': {
            const params: Record<string, string> = { grant_type: 'client_credentials', client_id: p.clientId };
            if (p.clientSecret) { params['client_secret'] = p.clientSecret; }
            if (p.scope) { params['scope'] = p.scope; }
            ({ token, expiresIn } = await postToken(p.tokenUrl, params));
            break;
        }
        case 'authorization_code': {
            ({ token, expiresIn } = await authorizationCodeFlow(p));
            break;
        }
        case 'device_code': {
            ({ token, expiresIn } = await deviceCodeFlow(p));
            break;
        }
        default:
            throw new Error(`Unsupported oauth2 grant type: ${p.grant}`);
    }

    cache.set(key, token, expiresIn);
    return token;
}

async function authorizationCodeFlow(p: OAuth2Params): Promise<{ token: string; expiresIn: number }> {
    // PKCE
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const state = crypto.randomBytes(16).toString('base64url');

    const redirectUri = `http://localhost:${p.redirectPort}/callback`;

    const authUrl = new URL(p.authUrl!);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', p.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    if (p.scope) { authUrl.searchParams.set('scope', p.scope); }

    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            const reqUrl = new URL(req.url!, `http://localhost:${p.redirectPort}`);
            if (reqUrl.pathname !== '/callback') { res.end('Not found'); return; }
            if (reqUrl.searchParams.get('state') !== state) {
                res.end('State mismatch'); reject(new Error('oauth2: state mismatch')); return;
            }
            const code = reqUrl.searchParams.get('code');
            if (!code) { res.end('Missing code'); reject(new Error('oauth2: missing code')); return; }
            res.end('<html><body><h2>Authorization successful — you can close this tab.</h2></body></html>');
            server.close();

            const params: Record<string, string> = {
                grant_type: 'authorization_code',
                code,
                redirect_uri: redirectUri,
                client_id: p.clientId,
                code_verifier: verifier,
            };
            if (p.clientSecret) { params['client_secret'] = p.clientSecret; }
            postToken(p.tokenUrl, params).then(resolve).catch(reject);
        });

        server.listen(parseInt(p.redirectPort!), () => {
            vscode.env.openExternal(vscode.Uri.parse(authUrl.toString()));
            vscode.window.showInformationMessage(`OAuth2: browser opened for authorization. Waiting for callback on port ${p.redirectPort}...`);
        });

        server.on('error', reject);
        global.setTimeout(() => { server.close(); reject(new Error('oauth2: timed out waiting for authorization (5 min)')); }, 5 * 60 * 1000);
    });
}

async function deviceCodeFlow(p: OAuth2Params): Promise<{ token: string; expiresIn: number }> {
    const body = new URLSearchParams({ client_id: p.clientId, ...(p.scope ? { scope: p.scope } : {}) }).toString();
    const dcData = await new Promise<any>((resolve, reject) => {
        const parsed = new URL(p.deviceUrl!);
        const lib = parsed.protocol === 'https:' ? https : http;
        const req = lib.request({
            method: 'POST',
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
        }, (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
                try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (e) { reject(e); }
            });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });

    const verificationUri = dcData.verification_uri || dcData.verification_url;
    const userCode = dcData.user_code;
    let interval = (dcData.interval || 5) * 1000;
    const expiresIn: number = dcData.expires_in || 300;

    await vscode.window.showInformationMessage(
        `OAuth2 Device Auth: go to ${verificationUri} and enter code: ${userCode}`,
        { modal: false },
        'Open Browser'
    ).then(sel => { if (sel === 'Open Browser') { vscode.env.openExternal(vscode.Uri.parse(verificationUri)); } });

    const deadline = Date.now() + expiresIn * 1000;
    while (Date.now() < deadline) {
        await new Promise(r => global.setTimeout(r, interval));
        try {
            const result = await postToken(p.tokenUrl, {
                grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                device_code: dcData.device_code,
                client_id: p.clientId,
            });
            return result;
        } catch (e: any) {
            if (e.message?.includes('authorization_pending')) { continue; }
            if (e.message?.includes('slow_down')) { interval += 5000; continue; }
            throw e;
        }
    }
    throw new Error('oauth2: device code expired');
}

interface CookieEntry {
    name: string;
    value: string;
    domain: string;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    expires?: number;
}

class CookieJar {
    private cookies: Map<string, CookieEntry[]> = new Map();
    private file?: string;

    constructor(file?: string) {
        this.file = file;
        if (file && fs.existsSync(file)) {
            try {
                const data = JSON.parse(fs.readFileSync(file, 'utf8'));
                for (const [domain, entries] of Object.entries(data)) {
                    this.cookies.set(domain, entries as CookieEntry[]);
                }
            } catch { /* ignore */ }
        }
    }

    getCookieHeader(url: URL): string {
        const domain = url.hostname;
        const urlPath = url.pathname;
        const isSecure = url.protocol === 'https:';
        const entries = this.cookies.get(domain) || [];
        return entries
            .filter(c => {
                if (c.secure && !isSecure) { return false; }
                if (!urlPath.startsWith(c.path || '/')) { return false; }
                if (c.expires && Date.now() > c.expires) { return false; }
                return true;
            })
            .map(c => `${c.name}=${c.value}`)
            .join('; ');
    }

    setCookies(url: URL, setCookieHeaders: string[]) {
        const domain = url.hostname;
        const existing = this.cookies.get(domain) || [];
        const existingMap = new Map(existing.map(c => [c.name, c]));

        for (const header of setCookieHeaders) {
            const parts = header.split(';').map(s => s.trim());
            const [nameVal, ...attrs] = parts;
            const eqIdx = nameVal.indexOf('=');
            if (eqIdx < 0) { continue; }
            const name = nameVal.substring(0, eqIdx).trim();
            const value = nameVal.substring(eqIdx + 1).trim();

            const entry: CookieEntry = { name, value, domain, path: '/', secure: false, httpOnly: false };
            for (const attr of attrs) {
                const attrLower = attr.toLowerCase();
                if (attrLower === 'secure') { entry.secure = true; }
                else if (attrLower === 'httponly') { entry.httpOnly = true; }
                else if (attrLower.startsWith('path=')) { entry.path = attr.substring(5); }
                else if (attrLower.startsWith('expires=')) {
                    const d = new Date(attr.substring(8));
                    if (!isNaN(d.getTime())) { entry.expires = d.getTime(); }
                }
            }
            existingMap.set(name, entry);
        }
        this.cookies.set(domain, Array.from(existingMap.values()));
    }

    save() {
        if (!this.file) { return; }
        const data: Record<string, CookieEntry[]> = {};
        for (const [domain, entries] of this.cookies) {
            data[domain] = entries;
        }
        try {
            fs.writeFileSync(this.file, JSON.stringify(data, null, 2));
        } catch { /* ignore */ }
    }
}

export function activate(context: vscode.ExtensionContext) {
    console.log('dot-http active');

    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider({ language: 'http', scheme: 'file' }, new HttpCodeLensProvider())
    );

    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            { language: 'http', scheme: 'file' },
            new HttpCompletionProvider(),
            '@', '{', ' ', '.'
        )
    );

    const httpSelector: vscode.DocumentSelector = { language: 'http', scheme: 'file' };

    context.subscriptions.push(
        vscode.languages.registerHoverProvider(httpSelector, new HttpHoverProvider()),
        vscode.languages.registerDocumentSymbolProvider(httpSelector, new HttpDocumentSymbolProvider()),
        vscode.languages.registerDefinitionProvider(httpSelector, new HttpDefinitionProvider()),
        vscode.languages.registerReferenceProvider(httpSelector, new HttpReferenceProvider()),
        vscode.languages.registerFoldingRangeProvider(httpSelector, new HttpFoldingRangeProvider())
    );

    // Diagnostics
    const diagnostics = vscode.languages.createDiagnosticCollection('dot-http');
    context.subscriptions.push(diagnostics);
    const refreshDiagnostics = (doc: vscode.TextDocument) => {
        if (doc.languageId !== 'http') { return; }
        diagnostics.set(doc.uri, computeDiagnostics(doc));
    };
    if (vscode.window.activeTextEditor) { refreshDiagnostics(vscode.window.activeTextEditor.document); }
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(refreshDiagnostics),
        vscode.workspace.onDidChangeTextDocument(e => refreshDiagnostics(e.document)),
        vscode.workspace.onDidCloseTextDocument(doc => diagnostics.delete(doc.uri))
    );

    // Fold / unfold all commands (scoped to the active .http editor)
    context.subscriptions.push(
        vscode.commands.registerCommand('dot-http.foldAll', () => vscode.commands.executeCommand('editor.foldAll')),
        vscode.commands.registerCommand('dot-http.unfoldAll', () => vscode.commands.executeCommand('editor.unfoldAll'))
    );

    context.subscriptions.push(
        vscode.workspace.registerTextDocumentContentProvider(RESPONSE_SCHEME, responseProvider)
    );

    context.subscriptions.push(vscode.commands.registerCommand('dot-http.runRequest', async (codeLensRange: vscode.Range) => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) { return; }

        const document = editor.document;
        const text = document.getText();
        const documentDir = path.dirname(document.uri.fsPath);

        // Parse file-level config (@env, @session)
        const fileConfig = parseFileConfig(text);

        // Process imports
        const visited = new Set<string>();
        visited.add(path.resolve(document.uri.fsPath));
        const imported = parseImports(text, documentDir, visited);

        const localBlocks = parseDocumentRequests(text);
        const requestBlocks = [...imported.blocks, ...localBlocks];

        const targetBlock = localBlocks.find(b =>
            codeLensRange.start.line >= b.startLine && codeLensRange.start.line <= b.endLine
        );

        if (!targetBlock) {
            vscode.window.showErrorMessage("Could not find request block");
            return;
        }

        // Resolve env file
        const envFileName = fileConfig.envName ? `${fileConfig.envName}.env` : '.env';
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || documentDir;

        const fileVariables = parseFileVariables(text);
        const envVariables = loadEnvFile(workspaceRoot, envFileName);
        const systemVariables = process.env as Record<string, string>;

        const globalVariables = {
            ...imported.variables,
            ...fileVariables,
            ...systemVariables,
            ...envVariables
        };

        // Cookie jar
        const cookieJar = fileConfig.sessionFile
            ? new CookieJar(path.resolve(workspaceRoot, fileConfig.sessionFile))
            : undefined;

        // OAuth2 cache
        const oauth2CacheFile = fileConfig.oauth2CacheFile
            ? path.resolve(workspaceRoot, fileConfig.oauth2CacheFile)
            : undefined;
        const vsConfig = vscode.workspace.getConfiguration('dot-http');
        const oauth2CacheFileSetting = vsConfig.get<string>('oauth2CacheFile') || '.tokens.json';
        const oauth2Cache = new OAuth2Cache(oauth2CacheFile ?? path.resolve(workspaceRoot, oauth2CacheFileSetting));

        // Build performer
        const config = vsConfig;
        const timeoutMs = parseTimeout(config.get<string>('timeout') || '');
        const followRedirects = config.get<boolean>('followRedirects') ?? true;

        const requestContext: Record<string, any> = { ...globalVariables };
        const assertionResults: { blockName: string; failures: string[] }[] = [];

        const performer = (reqText: string, block: RequestBlock) =>
            performRequest(reqText, { timeoutMs, followRedirects: block.noFollow ? false : followRedirects, cookieJar, oauth2Cache });

        try {
            const result = await executeRequestChain(targetBlock, requestBlocks, requestContext, performer, new Set(), assertionResults);
            cookieJar?.save();
            if (result) {
                await showResult(result, assertionResults);
            }
        } catch (error: any) {
            cookieJar?.save();
            vscode.window.showErrorMessage(`Error: ${error.message}`);
        }
    }));
}

export async function executeRequestChain(
    targetBlock: RequestBlock,
    allBlocks: RequestBlock[],
    context: Record<string, any>,
    performer: (text: string, block: RequestBlock) => Promise<ResponseData | null>,
    visited: Set<string> = new Set(),
    assertionResults: { blockName: string; failures: string[] }[] = []
): Promise<ResponseData | null> {
    if (targetBlock.name && visited.has(targetBlock.name)) {
        throw new Error(`Circular dependency detected: ${targetBlock.name}`);
    }
    if (targetBlock.name) { visited.add(targetBlock.name); }

    for (const dep of targetBlock.requires) {
        if (visited.has(dep.name)) {
            throw new Error(`Circular dependency detected: ${dep.name}`);
        }
        const dependencyBlock = allBlocks.find(b => b.name === dep.name);
        if (!dependencyBlock) {
            throw new Error(`Dependency not found: ${dep.name}`);
        }

        const depArgs: Record<string, string> = {};
        for (const [key, val] of Object.entries(dep.args)) {
            depArgs[key] = substituteVariables(val, context);
        }

        const childContext = { ...context, ...depArgs };
        const forceExecute = Object.keys(depArgs).length > 0;

        if (forceExecute || !context[dep.name]) {
            await executeRequestChain(dependencyBlock, allBlocks, childContext, performer, new Set(visited), assertionResults);
            for (const key in childContext) {
                const val = childContext[key];
                if (val && typeof val === 'object' && allBlocks.some(b => b.name === key)) {
                    context[key] = val;
                    if (key === dep.name && dep.alias) {
                        context[dep.alias] = val;
                    }
                }
            }
        }
    }

    const resolvedRequestText = substituteVariables(targetBlock.text, context);
    const result = await performer(resolvedRequestText, targetBlock);
    if (!result) { return null; }

    // Check assertions
    if (targetBlock.expectStatus !== undefined || (targetBlock.assertions?.length ?? 0) > 0) {
        const name = targetBlock.name || '(unnamed)';
        const failures = checkAssertions(targetBlock, result);
        assertionResults.push({ blockName: name, failures });
        if (failures.length > 0) {
            throw new Error(`Assertion failed in "${name}": ${failures.join('; ')}`);
        }
    }

    if (targetBlock.name) {
        let jsonBody: any = null;
        try { jsonBody = JSON.parse(result.body); } catch { /* ignore */ }
        context[targetBlock.name] = {
            body: jsonBody ?? result.body,
            headers: result.headers,
            response: { body: jsonBody ?? result.body, headers: result.headers }
        };
    }

    return result;
}

function checkAssertions(block: RequestBlock, result: ResponseData): string[] {
    const failures: string[] = [];

    if (block.expectStatus !== undefined && result.statusCode !== block.expectStatus) {
        failures.push(`expected status ${block.expectStatus}, got ${result.statusCode}`);
    }

    for (const a of block.assertions ?? []) {
        const got = extractAssertValue(a.target, result);
        if (!evalOp(got, a.op, a.value)) {
            failures.push(`${a.target} ${a.op} "${a.value}" (got: "${got}")`);
        }
    }
    return failures;
}

function extractAssertValue(target: string, result: ResponseData): string {
    if (target === 'status') { return String(result.statusCode); }
    if (target.startsWith('header.')) {
        const name = target.substring(7);
        const val = result.headers[name] ?? result.headers[name.toLowerCase()];
        return Array.isArray(val) ? val.join(', ') : (val || '');
    }
    if (target.startsWith('body.')) {
        const jsonPath = target.substring(5);
        try {
            let obj = JSON.parse(result.body);
            for (const part of jsonPath.split('.')) {
                if (obj && typeof obj === 'object') { obj = obj[part]; }
                else { return ''; }
            }
            return String(obj ?? '');
        } catch { return ''; }
    }
    return '';
}

function evalOp(got: string, op: string, expected: string): boolean {
    switch (op) {
        case '==': return got === expected;
        case '!=': return got !== expected;
        case 'contains': return got.includes(expected);
        case '!contains': return !got.includes(expected);
    }
    return false;
}

class HttpCodeLensProvider implements vscode.CodeLensProvider {
    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];
        const text = document.getText();
        const requestBlocks = parseDocumentRequests(text);
        const methodRegex = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+/;

        for (const block of requestBlocks) {
            const lines = block.text.split(/\r?\n/);
            for (let i = 0; i < lines.length; i++) {
                if (methodRegex.test(lines[i])) {
                    const absLine = block.startLine + i;
                    const range = new vscode.Range(absLine, 0, absLine, lines[i].length);
                    lenses.push(new vscode.CodeLens(range, {
                        title: "Run Request",
                        command: "dot-http.runRequest",
                        arguments: [range]
                    }));
                    break;
                }
            }
        }
        return lenses;
    }
}

// ---------------------------------------------------------------------------
// Autocomplete
// ---------------------------------------------------------------------------

interface DirectiveSpec {
    label: string;          // text inserted, e.g. "@name = "
    detail: string;         // short right-hand description
    doc: string;            // hover documentation
    scope: 'file' | 'request' | 'both';
}

const DIRECTIVE_SPECS: DirectiveSpec[] = [
    // File-level
    { label: '@env', detail: 'load <name>.env', doc: 'Load environment variables from `<name>.env`.', scope: 'file' },
    { label: '@session', detail: 'persist cookies', doc: 'Persist cookies to a JSON file across requests.', scope: 'file' },
    { label: '@import', detail: 'import another .http file', doc: 'Import named requests and variables from another `.http` file.', scope: 'file' },
    { label: '@oauth2-cache', detail: 'persist OAuth2 tokens', doc: 'Persist OAuth2 tokens to a file (e.g. `.tokens.json`).', scope: 'file' },
    // Per-request
    { label: '@name', detail: 'name a request', doc: 'Name a request so it can be referenced via `@requires`.', scope: 'request' },
    { label: '@requires', detail: 'declare dependency', doc: 'Run another named request first. Supports `foo(key=val)` and trailing `as <alias>`.', scope: 'request' },
    { label: '@expect', detail: 'assert status code', doc: 'Assert the response status code, e.g. `@expect 201`.', scope: 'request' },
    { label: '@assert', detail: 'assert body/header', doc: 'Assert on body/header. Ops: `==`, `!=`, `contains`, `!contains`.', scope: 'request' },
    { label: '@no-follow', detail: "don't follow redirects", doc: "Don't follow redirects for this request.", scope: 'request' },
    // OAuth2 per-request
    { label: '@oauth2-grant', detail: 'client_credentials | authorization_code | device_code', doc: 'OAuth2 grant type.', scope: 'request' },
    { label: '@oauth2-token-url', detail: 'token endpoint', doc: 'OAuth2 token endpoint URL.', scope: 'request' },
    { label: '@oauth2-auth-url', detail: 'authorization endpoint', doc: 'Authorization endpoint URL (authorization_code only).', scope: 'request' },
    { label: '@oauth2-device-url', detail: 'device endpoint', doc: 'Device authorization endpoint URL (device_code only).', scope: 'request' },
    { label: '@oauth2-client-id', detail: 'client id', doc: 'OAuth2 client id.', scope: 'request' },
    { label: '@oauth2-client-secret', detail: 'client secret (optional)', doc: 'OAuth2 client secret. Optional for public clients.', scope: 'request' },
    { label: '@oauth2-scope', detail: 'scope', doc: 'OAuth2 scope.', scope: 'request' },
    { label: '@oauth2-redirect-port', detail: 'callback port', doc: 'Local callback port for authorization_code (default 9876).', scope: 'request' },
];

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'];

const COMMON_HEADERS = [
    'Accept', 'Accept-Encoding', 'Accept-Language', 'Authorization', 'Cache-Control',
    'Content-Type', 'Content-Length', 'Cookie', 'Host', 'Origin', 'Referer',
    'User-Agent', 'X-Requested-With', 'X-Api-Key',
];

const CONTENT_TYPES = [
    'application/json', 'application/x-www-form-urlencoded', 'application/graphql',
    'application/xml', 'multipart/form-data', 'text/plain', 'text/html',
];

const ASSERT_TARGETS = ['status', 'body.', 'header.'];
const ASSERT_OPS = ['==', '!=', 'contains', '!contains'];
const OAUTH2_GRANTS = ['client_credentials', 'authorization_code', 'device_code'];

export type CompletionMode =
    | { kind: 'variable'; prefix: string }
    | { kind: 'requestName' }
    | { kind: 'assertTarget' }
    | { kind: 'assertOp' }
    | { kind: 'oauth2Grant' }
    | { kind: 'contentType' }
    | { kind: 'directive' }
    | { kind: 'methodOrHeader' }
    | { kind: 'none' };

/**
 * Decide which completion set a line prefix should produce. Pure (no vscode
 * dependency) so it can be unit-tested directly. Order matters: more specific
 * contexts are checked first.
 */
export function completionContext(linePrefix: string): CompletionMode {
    // 1. Inside {{ }} — variable names
    const varMatch = linePrefix.match(/\{\{(?:\$env\s+)?([^\s}]*)$/);
    if (varMatch) { return { kind: 'variable', prefix: varMatch[1] }; }

    // 2. @requires = <name> — request names
    if (/^\s*@requires\s*=\s*(\w*)$/.test(linePrefix)) { return { kind: 'requestName' }; }

    // 3. @assert <target> <op> — targets then ops
    if (/^\s*@assert\s+(\S*)$/.test(linePrefix)) { return { kind: 'assertTarget' }; }
    if (/^\s*@assert\s+\S+\s+(\S*)$/.test(linePrefix)) { return { kind: 'assertOp' }; }

    // 4. @oauth2-grant = — grant types
    if (/^\s*@oauth2-grant\s*=\s*\w*$/.test(linePrefix)) { return { kind: 'oauth2Grant' }; }

    // 5. Content-Type: — content type values
    if (/^\s*Content-Type\s*:\s*[\w/+.-]*$/i.test(linePrefix)) { return { kind: 'contentType' }; }

    // 6. Line starts with @ — directive names
    if (/^\s*@[\w-]*$/.test(linePrefix)) { return { kind: 'directive' }; }

    // 7. Empty / start of line — HTTP methods and header names
    if (/^\s*[A-Za-z-]*$/.test(linePrefix)) { return { kind: 'methodOrHeader' }; }

    return { kind: 'none' };
}

class HttpCompletionProvider implements vscode.CompletionItemProvider {
    provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position
    ): vscode.CompletionItem[] {
        const lineText = document.lineAt(position.line).text;
        const linePrefix = lineText.substring(0, position.character);
        const ctx = completionContext(linePrefix);

        switch (ctx.kind) {
            case 'variable':
                return this.variableCompletions(document, ctx.prefix);
            case 'requestName':
                return this.requestNameCompletions(document);
            case 'assertTarget':
                return ASSERT_TARGETS.map(t => {
                    const item = new vscode.CompletionItem(t, vscode.CompletionItemKind.Field);
                    item.detail = 'assert target';
                    if (t.endsWith('.')) { item.command = { command: 'editor.action.triggerSuggest', title: '' }; }
                    return item;
                });
            case 'assertOp':
                return ASSERT_OPS.map(op => {
                    const item = new vscode.CompletionItem(op, vscode.CompletionItemKind.Operator);
                    item.detail = 'assert operator';
                    return item;
                });
            case 'oauth2Grant':
                return OAUTH2_GRANTS.map(g => {
                    const item = new vscode.CompletionItem(g, vscode.CompletionItemKind.EnumMember);
                    item.detail = 'oauth2 grant';
                    return item;
                });
            case 'contentType':
                return CONTENT_TYPES.map(ct => {
                    const item = new vscode.CompletionItem(ct, vscode.CompletionItemKind.Value);
                    item.detail = 'content type';
                    return item;
                });
            case 'directive':
                return this.directiveCompletions();
            case 'methodOrHeader':
                return [...this.methodCompletions(), ...this.headerCompletions()];
            default:
                return [];
        }
    }

    private directiveCompletions(): vscode.CompletionItem[] {
        return DIRECTIVE_SPECS.map(spec => {
            const item = new vscode.CompletionItem(spec.label, vscode.CompletionItemKind.Keyword);
            item.detail = spec.detail;
            item.documentation = new vscode.MarkdownString(spec.doc);
            if (spec.label === '@no-follow') {
                item.insertText = 'no-follow';
            } else {
                // strip the leading '@' (already typed as trigger) and add ' = '
                item.insertText = new vscode.SnippetString(`${spec.label.substring(1)} = $0`);
                item.command = { command: 'editor.action.triggerSuggest', title: '' };
            }
            // Sort file-level and request-level together but keep @name/@requires near top
            item.sortText = spec.scope === 'request' ? '1' + spec.label : '2' + spec.label;
            return item;
        });
    }

    private methodCompletions(): vscode.CompletionItem[] {
        return HTTP_METHODS.map(m => {
            const item = new vscode.CompletionItem(m, vscode.CompletionItemKind.Method);
            item.detail = 'HTTP method';
            item.insertText = new vscode.SnippetString(`${m} `);
            item.sortText = '0' + m;
            return item;
        });
    }

    private headerCompletions(): vscode.CompletionItem[] {
        return COMMON_HEADERS.map(h => {
            const item = new vscode.CompletionItem(h, vscode.CompletionItemKind.Field);
            item.detail = 'HTTP header';
            item.insertText = new vscode.SnippetString(`${h}: $0`);
            if (h === 'Content-Type') {
                item.command = { command: 'editor.action.triggerSuggest', title: '' };
            }
            item.sortText = '1' + h;
            return item;
        });
    }

    private requestNameCompletions(document: vscode.TextDocument): vscode.CompletionItem[] {
        const blocks = parseDocumentRequests(document.getText());
        const seen = new Set<string>();
        const items: vscode.CompletionItem[] = [];
        for (const block of blocks) {
            if (block.name && !seen.has(block.name)) {
                seen.add(block.name);
                const item = new vscode.CompletionItem(block.name, vscode.CompletionItemKind.Reference);
                item.detail = 'named request';
                items.push(item);
            }
        }
        return items;
    }

    private variableCompletions(document: vscode.TextDocument, prefix: string): vscode.CompletionItem[] {
        const names = new Set<string>();

        // File variables
        for (const name of Object.keys(parseFileVariables(document.getText()))) {
            names.add(name);
        }

        // Imported variables
        const documentDir = path.dirname(document.uri.fsPath);
        try {
            const visited = new Set<string>([path.resolve(document.uri.fsPath)]);
            const imported = parseImports(document.getText(), documentDir, visited);
            for (const name of Object.keys(imported.variables)) { names.add(name); }
        } catch { /* ignore */ }

        // .env variables (default + any @env target)
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || documentDir;
        const fileConfig = parseFileConfig(document.getText());
        const envFiles = new Set<string>(['.env']);
        if (fileConfig.envName) { envFiles.add(`${fileConfig.envName}.env`); }
        for (const envFile of envFiles) {
            for (const name of Object.keys(loadEnvFile(workspaceRoot, envFile))) { names.add(name); }
        }

        // dot-path completion against named request bodies isn't statically known,
        // but we can suggest the top-level request names too (they expose .body/.headers).
        for (const block of parseDocumentRequests(document.getText())) {
            if (block.name) { names.add(block.name); }
        }

        const items: vscode.CompletionItem[] = [];
        for (const name of names) {
            const item = new vscode.CompletionItem(name, vscode.CompletionItemKind.Variable);
            item.detail = 'variable';
            items.push(item);
        }
        return items;
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for editor features (hover, diagnostics, navigation)
// ---------------------------------------------------------------------------

/** A variable reference `{{...}}` found in the document, with its location. */
interface VarRef {
    /** Full reference name as written, e.g. `getPost.body.id` or `USER`. */
    name: string;
    /** Top-level segment used for lookups, e.g. `getPost` or `USER`. */
    root: string;
    line: number;
    /** Start column of `root` within the line. */
    startCol: number;
    /** End column of `root` within the line. */
    endCol: number;
}

const VAR_REF_REGEX = /\{\{(?:\$env\s+)?([^\s}]+)\}\}/g;

/** Find every `{{var}}` reference in the document with precise positions. */
function findVarRefs(text: string): VarRef[] {
    const refs: VarRef[] = [];
    const lines = text.split(/\r?\n/);
    for (let line = 0; line < lines.length; line++) {
        const re = new RegExp(VAR_REF_REGEX.source, 'g');
        let m: RegExpExecArray | null;
        while ((m = re.exec(lines[line])) !== null) {
            const full = m[1];
            const root = full.split('.')[0];
            // column where the captured group starts within the match
            const groupStart = m.index + m[0].indexOf(full);
            refs.push({
                name: full,
                root,
                line,
                startCol: groupStart,
                endCol: groupStart + root.length,
            });
        }
    }
    return refs;
}

// Directives use bare `@key = value`; a leading `#` makes the line a comment
// (a disabled directive). These helpers match the bare form to stay consistent
// with parseDocumentRequests, which is what actually drives execution.

/** Locate the line and column range of each `@name = X` declaration. */
function findNameDeclarations(text: string): { name: string; line: number; startCol: number; endCol: number }[] {
    const out: { name: string; line: number; startCol: number; endCol: number }[] = [];
    const lines = text.split(/\r?\n/);
    const re = /^(\s*@name\s*=\s*)(\w+)/;
    for (let line = 0; line < lines.length; line++) {
        const m = lines[line].match(re);
        if (m) {
            const startCol = m[1].length;
            out.push({ name: m[2], line, startCol, endCol: startCol + m[2].length });
        }
    }
    return out;
}

/** Locate every `@requires = X` reference (the X token). */
function findRequiresRefs(text: string): { name: string; line: number; startCol: number; endCol: number }[] {
    const out: { name: string; line: number; startCol: number; endCol: number }[] = [];
    const lines = text.split(/\r?\n/);
    const re = /^(\s*@requires\s*=\s*)(\w+)/;
    for (let line = 0; line < lines.length; line++) {
        const m = lines[line].match(re);
        if (m) {
            const startCol = m[1].length;
            out.push({ name: m[2], line, startCol, endCol: startCol + m[2].length });
        }
    }
    return out;
}

/**
 * Collect the names known to a document for variable/reference resolution:
 * file variables, imported variables, .env variables, and named requests.
 */
function collectKnownNames(document: vscode.TextDocument): {
    fileVars: Record<string, string>;
    envVars: Record<string, string>;
    importedVars: Record<string, string>;
    requestNames: Set<string>;
} {
    const text = document.getText();
    const documentDir = path.dirname(document.uri.fsPath);
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || documentDir;

    const fileVars = parseFileVariables(text);

    let importedVars: Record<string, string> = {};
    try {
        const visited = new Set<string>([path.resolve(document.uri.fsPath)]);
        importedVars = parseImports(text, documentDir, visited).variables;
    } catch { /* ignore */ }

    const fileConfig = parseFileConfig(text);
    const envVars: Record<string, string> = {};
    const envFiles = new Set<string>(['.env']);
    if (fileConfig.envName) { envFiles.add(`${fileConfig.envName}.env`); }
    for (const envFile of envFiles) {
        Object.assign(envVars, loadEnvFile(workspaceRoot, envFile));
    }

    const requestNames = new Set<string>();
    for (const b of parseDocumentRequests(text)) { if (b.name) { requestNames.add(b.name); } }

    return { fileVars, envVars, importedVars, requestNames };
}

// ---------------------------------------------------------------------------
// Hover
// ---------------------------------------------------------------------------

class HttpHoverProvider implements vscode.HoverProvider {
    provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
        const text = document.getText();

        // Directive hover
        const lineText = document.lineAt(position.line).text;
        const dirMatch = lineText.match(/@[\w-]+/);
        if (dirMatch) {
            const start = lineText.indexOf(dirMatch[0]);
            const end = start + dirMatch[0].length;
            if (position.character >= start && position.character <= end) {
                const spec = DIRECTIVE_SPECS.find(s => s.label === dirMatch[0]);
                if (spec) {
                    const md = new vscode.MarkdownString(`**${spec.label}** — ${spec.detail}\n\n${spec.doc}`);
                    return new vscode.Hover(md, new vscode.Range(position.line, start, position.line, end));
                }
            }
        }

        // Variable hover
        const ref = findVarRefs(text).find(r =>
            r.line === position.line && position.character >= r.startCol && position.character <= r.endCol
        );
        if (ref) {
            const { fileVars, envVars, importedVars, requestNames } = collectKnownNames(document);
            const md = new vscode.MarkdownString();
            // precedence: system env > .env > file var (system env not statically resolvable)
            if (Object.prototype.hasOwnProperty.call(envVars, ref.root)) {
                md.appendMarkdown(`**${ref.root}** _(\`.env\`)_\n\n\`${envVars[ref.root]}\``);
            } else if (Object.prototype.hasOwnProperty.call(fileVars, ref.root)) {
                md.appendMarkdown(`**${ref.root}** _(file variable)_\n\n\`${fileVars[ref.root]}\``);
            } else if (Object.prototype.hasOwnProperty.call(importedVars, ref.root)) {
                md.appendMarkdown(`**${ref.root}** _(imported)_\n\n\`${importedVars[ref.root]}\``);
            } else if (requestNames.has(ref.root)) {
                md.appendMarkdown(`**${ref.root}** _(named request)_\n\nResolved at runtime from the response — e.g. \`{{${ref.root}.body.field}}\`, \`{{${ref.root}.headers.Name}}\`.`);
            } else {
                md.appendMarkdown(`**${ref.root}** — may resolve from a system environment variable, or is undefined.`);
            }
            return new vscode.Hover(md, new vscode.Range(ref.line, ref.startCol, ref.line, ref.endCol));
        }

        return undefined;
    }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

export function computeDiagnostics(document: vscode.TextDocument): vscode.Diagnostic[] {
    const text = document.getText();
    const diags: vscode.Diagnostic[] = [];

    const { fileVars, envVars, importedVars, requestNames } = collectKnownNames(document);

    // Undefined variable references (skip names that could come from system env —
    // we only warn when it's clearly none of the known sources and not all-caps env-style).
    for (const ref of findVarRefs(text)) {
        const known =
            Object.prototype.hasOwnProperty.call(fileVars, ref.root) ||
            Object.prototype.hasOwnProperty.call(envVars, ref.root) ||
            Object.prototype.hasOwnProperty.call(importedVars, ref.root) ||
            requestNames.has(ref.root) ||
            Object.prototype.hasOwnProperty.call(process.env, ref.root);
        if (!known) {
            const range = new vscode.Range(ref.line, ref.startCol, ref.line, ref.endCol);
            diags.push(new vscode.Diagnostic(
                range,
                `Undefined variable "${ref.root}". Define it with @${ref.root} = ..., in a .env file, or as a named request.`,
                vscode.DiagnosticSeverity.Warning
            ));
        }
    }

    // @requires pointing at a non-existent @name
    for (const req of findRequiresRefs(text)) {
        if (!requestNames.has(req.name)) {
            const range = new vscode.Range(req.line, req.startCol, req.line, req.endCol);
            diags.push(new vscode.Diagnostic(
                range,
                `@requires references unknown request "${req.name}". No @name = ${req.name} found in this file or its imports.`,
                vscode.DiagnosticSeverity.Error
            ));
        }
    }

    // Duplicate @name declarations
    const seenNames = new Map<string, number>();
    for (const decl of findNameDeclarations(text)) {
        const prev = seenNames.get(decl.name);
        if (prev !== undefined) {
            const range = new vscode.Range(decl.line, decl.startCol, decl.line, decl.endCol);
            diags.push(new vscode.Diagnostic(
                range,
                `Duplicate request name "${decl.name}" (first defined on line ${prev + 1}).`,
                vscode.DiagnosticSeverity.Warning
            ));
        } else {
            seenNames.set(decl.name, decl.line);
        }
    }

    // Malformed @assert (has content but doesn't match target op value with a valid op)
    const lines = text.split(/\r?\n/);
    const assertLine = /^\s*@assert\s+(.+)$/;
    const validAssert = /^\s*@assert\s+\S+\s+(==|!=|contains|!contains)\s+.+$/;
    const knownOps = new Set(['==', '!=', 'contains', '!contains']);
    for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(assertLine);
        if (m && !validAssert.test(lines[i])) {
            const parts = m[1].trim().split(/\s+/);
            let message = 'Invalid @assert. Expected: @assert <target> <op> <value>';
            if (parts.length >= 2 && !knownOps.has(parts[1])) {
                message = `Invalid @assert operator "${parts[1]}". Use one of: ==, !=, contains, !contains.`;
            }
            const start = lines[i].indexOf('@assert');
            const range = new vscode.Range(i, start, i, lines[i].length);
            diags.push(new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Error));
        }
    }

    return diags;
}

// ---------------------------------------------------------------------------
// Document symbols / outline
// ---------------------------------------------------------------------------

class HttpDocumentSymbolProvider implements vscode.DocumentSymbolProvider {
    provideDocumentSymbols(document: vscode.TextDocument): vscode.DocumentSymbol[] {
        const text = document.getText();
        const blocks = parseDocumentRequests(text);
        const methodRegex = /^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)/;
        const symbols: vscode.DocumentSymbol[] = [];

        for (const block of blocks) {
            const blockLines = block.text.split(/\r?\n/);
            let detail = '';
            let selectionLine = block.startLine;
            for (let i = 0; i < blockLines.length; i++) {
                const mm = blockLines[i].match(methodRegex);
                if (mm) {
                    detail = `${mm[1]} ${mm[2]}`;
                    selectionLine = block.startLine + i;
                    break;
                }
            }
            // Skip empty trailing blocks with no request line and no name
            if (!detail && !block.name) { continue; }

            const label = block.name ?? (detail || '(request)');
            const fullRange = new vscode.Range(block.startLine, 0, block.endLine, Number.MAX_SAFE_INTEGER);
            const selRange = new vscode.Range(selectionLine, 0, selectionLine, Number.MAX_SAFE_INTEGER);
            const sym = new vscode.DocumentSymbol(
                label,
                block.name ? detail : '',
                vscode.SymbolKind.Function,
                fullRange,
                selRange
            );
            symbols.push(sym);
        }
        return symbols;
    }
}

// ---------------------------------------------------------------------------
// Go-to-definition  &  find-references
// ---------------------------------------------------------------------------

/** Returns the word/token under the cursor for @name/@requires/{{var}} contexts. */
function tokenAt(document: vscode.TextDocument, position: vscode.Position): { kind: 'name' | 'variable'; value: string } | undefined {
    const text = document.getText();

    // @requires = X  →  request name
    const req = findRequiresRefs(text).find(r =>
        r.line === position.line && position.character >= r.startCol && position.character <= r.endCol);
    if (req) { return { kind: 'name', value: req.name }; }

    // @name = X  →  request name (self / for references)
    const decl = findNameDeclarations(text).find(r =>
        r.line === position.line && position.character >= r.startCol && position.character <= r.endCol);
    if (decl) { return { kind: 'name', value: decl.name }; }

    // {{ var }}
    const ref = findVarRefs(text).find(r =>
        r.line === position.line && position.character >= r.startCol && position.character <= r.endCol);
    if (ref) { return { kind: 'variable', value: ref.root }; }

    return undefined;
}

class HttpDefinitionProvider implements vscode.DefinitionProvider {
    provideDefinition(document: vscode.TextDocument, position: vscode.Position): vscode.Location[] {
        const token = tokenAt(document, position);
        if (!token) { return []; }
        const text = document.getText();
        const locations: vscode.Location[] = [];

        if (token.kind === 'name') {
            for (const decl of findNameDeclarations(text)) {
                if (decl.name === token.value) {
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(decl.line, decl.startCol, decl.line, decl.endCol)));
                }
            }
        } else {
            // variable → its @var declaration in this file (if any)
            const declRe = new RegExp(`^(\\s*@)(${escapeRegExp(token.value)})\\s*=`);
            const lines = text.split(/\r?\n/);
            for (let i = 0; i < lines.length; i++) {
                const m = lines[i].match(declRe);
                if (m) {
                    const startCol = m[1].length;
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(i, startCol, i, startCol + token.value.length)));
                }
            }
            // or a named request that exposes it
            for (const decl of findNameDeclarations(text)) {
                if (decl.name === token.value) {
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(decl.line, decl.startCol, decl.line, decl.endCol)));
                }
            }
        }
        return locations;
    }
}

class HttpReferenceProvider implements vscode.ReferenceProvider {
    provideReferences(document: vscode.TextDocument, position: vscode.Position): vscode.Location[] {
        const token = tokenAt(document, position);
        if (!token) { return []; }
        const text = document.getText();
        const locations: vscode.Location[] = [];

        if (token.kind === 'name') {
            // every @requires = name and {{name...}}
            for (const req of findRequiresRefs(text)) {
                if (req.name === token.value) {
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(req.line, req.startCol, req.line, req.endCol)));
                }
            }
            for (const ref of findVarRefs(text)) {
                if (ref.root === token.value) {
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(ref.line, ref.startCol, ref.line, ref.endCol)));
                }
            }
            for (const decl of findNameDeclarations(text)) {
                if (decl.name === token.value) {
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(decl.line, decl.startCol, decl.line, decl.endCol)));
                }
            }
        } else {
            for (const ref of findVarRefs(text)) {
                if (ref.root === token.value) {
                    locations.push(new vscode.Location(document.uri,
                        new vscode.Range(ref.line, ref.startCol, ref.line, ref.endCol)));
                }
            }
        }
        return locations;
    }
}

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Folding ranges (collapse each ### request block)
// ---------------------------------------------------------------------------

class HttpFoldingRangeProvider implements vscode.FoldingRangeProvider {
    provideFoldingRanges(document: vscode.TextDocument): vscode.FoldingRange[] {
        const ranges: vscode.FoldingRange[] = [];
        for (const block of parseDocumentRequests(document.getText())) {
            // only fold blocks that span more than one line
            if (block.endLine > block.startLine) {
                ranges.push(new vscode.FoldingRange(block.startLine, block.endLine, vscode.FoldingRangeKind.Region));
            }
        }
        return ranges;
    }
}

function parseFileConfig(text: string): FileConfig {
    const config: FileConfig = {};
    const envRegex = /^\s*@env\s*=\s*(.+?)\s*$/m;
    const sessionRegex = /^\s*@session\s*=\s*(.+?)\s*$/m;
    const oauth2CacheRegex = /^\s*@oauth2-cache\s*=\s*(.+?)\s*$/m;
    const envMatch = text.match(envRegex);
    if (envMatch) { config.envName = envMatch[1]; }
    const sessionMatch = text.match(sessionRegex);
    if (sessionMatch) { config.sessionFile = sessionMatch[1]; }
    const oauth2CacheMatch = text.match(oauth2CacheRegex);
    if (oauth2CacheMatch) { config.oauth2CacheFile = oauth2CacheMatch[1]; }
    return config;
}

function parseDocumentRequests(text: string): RequestBlock[] {
    const lines = text.split(/\r?\n/);
    const blocks: RequestBlock[] = [];
    let currentLines: string[] = [];
    let currentStartLine = 0;

    const nameRegex = /^\s*@name\s*=\s*(\w+)/;
    const requiresRegex = /^\s*@requires\s*=\s*(\w+)(?:\((.*?)\))?(?:\s+as\s+(\w+))?\s*$/;
    const expectRegex = /^\s*@expect\s+(\d+)/;
    const assertRegex = /^\s*@assert\s+(\S+)\s+(==|!=|contains|!contains)\s+(.+?)\s*$/;
    const noFollowRegex = /^\s*@no-follow/;

    const processBlock = () => {
        if (currentLines.length === 0) { return; }
        const blockText = currentLines.join('\n');
        let name: string | undefined;
        const requires: Dependency[] = [];
        const assertions: Assertion[] = [];
        let expectStatus: number | undefined;
        let noFollow = false;

        for (const l of currentLines) {
            const nameMatch = l.match(nameRegex);
            if (nameMatch) { name = nameMatch[1]; }

            const requiresMatch = l.match(requiresRegex);
            if (requiresMatch) {
                const args: Record<string, string> = {};
                if (requiresMatch[2]) {
                    for (const part of requiresMatch[2].split(',')) {
                        const [k, v] = part.split('=').map(s => s.trim());
                        if (k && v) { args[k] = v; }
                    }
                }
                requires.push({ name: requiresMatch[1], args, alias: requiresMatch[3] });
            }

            const expectMatch = l.match(expectRegex);
            if (expectMatch) { expectStatus = parseInt(expectMatch[1], 10); }

            const assertMatch = l.match(assertRegex);
            if (assertMatch) {
                assertions.push({ target: assertMatch[1], op: assertMatch[2] as Assertion['op'], value: assertMatch[3] });
            }

            if (noFollowRegex.test(l)) { noFollow = true; }
        }

        blocks.push({
            text: blockText,
            startLine: currentStartLine,
            endLine: currentStartLine + currentLines.length - 1,
            name,
            requires,
            expectStatus,
            assertions,
            noFollow
        });
    };

    for (let i = 0; i <= lines.length; i++) {
        const line = i < lines.length ? lines[i] : '###';
        if (line.trim().startsWith('###')) {
            processBlock();
            currentLines = [];
            currentStartLine = i + 1;
        } else {
            currentLines.push(line);
        }
    }
    return blocks;
}

async function performRequest(
    requestText: string,
    opts: { timeoutMs: number; followRedirects: boolean; cookieJar?: CookieJar; oauth2Cache?: OAuth2Cache }
): Promise<ResponseData | null> {
    const parsed = parseRequest(requestText);
    if (!parsed) { throw new Error("Invalid request format"); }

    let { method, url, headers, body } = parsed;

    // OAuth2: acquire token and inject Authorization header if not already set
    const lines = requestText.split(/\r?\n/);
    const oauthParams = parseOAuth2Params(lines);
    if (oauthParams && !headers['Authorization'] && !headers['authorization']) {
        const cache = opts.oauth2Cache ?? new OAuth2Cache();
        const token = await acquireOAuth2Token(oauthParams, cache);
        headers['Authorization'] = `Bearer ${token}`;
    }

    // GraphQL: auto-wrap
    const ct = headers['Content-Type'] || headers['content-type'] || '';
    if (ct.includes('application/graphql') && body) {
        body = JSON.stringify({ query: body.trim() });
        headers['Content-Type'] = 'application/json';
        delete headers['content-type'];
    }

    return makeRequest(method, url, headers, body, opts);
}

async function showResult(
    responseData: ResponseData,
    assertionResults: { blockName: string; failures: string[] }[]
) {
    const headerLines = Object.entries(responseData.headers)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`);

    let body = responseData.body;
    try {
        body = JSON.stringify(JSON.parse(body), null, 2);
    } catch { /* not JSON */ }

    const parts = [
        `HTTP/1.1 ${responseData.statusCode} ${responseData.statusMessage}`,
        ...headerLines,
        '',
        body
    ];

    if (assertionResults.length > 0) {
        parts.push('', '--- Assertions ---');
        for (const r of assertionResults) {
            if (r.failures.length === 0) {
                parts.push(`✓ ${r.blockName}: all passed`);
            } else {
                for (const f of r.failures) {
                    parts.push(`✗ ${r.blockName}: ${f}`);
                }
            }
        }
    }

    const content = parts.join('\n');
    const config = vscode.workspace.getConfiguration('dot-http');
    const viewMode = config.get<string>('responseViewMode') || 'reuseTab';

    if (viewMode === 'output') {
        if (!outputChannel) { outputChannel = vscode.window.createOutputChannel("dot-http"); }
        outputChannel.clear();
        outputChannel.append(content);
        outputChannel.show(true);
    } else if (viewMode === 'reuseTab') {
        const uri = vscode.Uri.parse(`${RESPONSE_SCHEME}:response.http`);
        responseProvider.update(uri, content);
        const existing = vscode.window.visibleTextEditors.find(
            e => e.document.uri.toString() === uri.toString()
        );
        if (existing) {
            await vscode.window.showTextDocument(existing.document, {
                viewColumn: existing.viewColumn,
                preserveFocus: true
            });
        } else {
            const doc = await vscode.workspace.openTextDocument(uri);
            await vscode.window.showTextDocument(doc, {
                preview: false,
                preserveFocus: true
            });
        }
    } else {
        const doc = await vscode.workspace.openTextDocument({ content, language: 'http' });
        await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside });
    }
}

function parseRequest(text: string): { method: string; url: string; headers: Record<string, string>; body: string | null } | null {
    const lines = text.split(/\r?\n/);
    let methodLineIndex = -1;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line && !line.startsWith('#') && !line.startsWith('//') && !line.startsWith('@')) {
            methodLineIndex = i;
            break;
        }
    }
    if (methodLineIndex === -1) { return null; }

    const methodParts = lines[methodLineIndex].trim().split(/\s+/);
    if (methodParts.length < 2) { return null; }

    const method = methodParts[0];
    const url = methodParts[1];
    const headers: Record<string, string> = {};
    let bodyStartIndex = -1;

    for (let i = methodLineIndex + 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === '') { bodyStartIndex = i + 1; break; }
        if (line.startsWith('#') || line.startsWith('//') || line.startsWith('@')) { continue; }
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            headers[line.substring(0, colonIndex).trim()] = line.substring(colonIndex + 1).trim();
        }
    }

    const body = bodyStartIndex !== -1 && bodyStartIndex < lines.length
        ? lines.slice(bodyStartIndex).join('\n')
        : null;

    return { method, url, headers, body };
}

function makeRequest(
    method: string,
    requestUrl: string,
    headers: Record<string, string>,
    body: string | null,
    opts: { timeoutMs: number; followRedirects: boolean; cookieJar?: CookieJar },
    redirectCount = 0
): Promise<ResponseData> {
    return new Promise((resolve, reject) => {
        let parsedUrl: URL;
        try { parsedUrl = new URL(requestUrl); } catch (e) { return reject(new Error(`Invalid URL: ${requestUrl}`)); }

        // Inject cookies
        if (opts.cookieJar) {
            const cookieHeader = opts.cookieJar.getCookieHeader(parsedUrl);
            if (cookieHeader) { headers['Cookie'] = cookieHeader; }
        }

        const options: http.RequestOptions = {
            method,
            headers,
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            protocol: parsedUrl.protocol,
            ...(opts.timeoutMs > 0 ? { timeout: opts.timeoutMs } : {})
        };

        const lib = parsedUrl.protocol === 'https:' ? https : http;

        const req = lib.request(options, (res) => {
            // Handle Set-Cookie
            if (opts.cookieJar && res.headers['set-cookie']) {
                const setCookies = Array.isArray(res.headers['set-cookie'])
                    ? res.headers['set-cookie']
                    : [res.headers['set-cookie']];
                opts.cookieJar.setCookies(parsedUrl, setCookies);
            }

            // Handle redirects
            const isRedirect = [301, 302, 303, 307, 308].includes(res.statusCode || 0);
            if (opts.followRedirects && isRedirect && res.headers.location && redirectCount < 10) {
                const location = res.headers.location;
                const nextUrl = location.startsWith('http') ? location : new URL(location, requestUrl).toString();
                const nextMethod = res.statusCode === 303 ? 'GET' : method;
                const nextBody = res.statusCode === 303 ? null : body;
                res.resume(); // drain
                resolve(makeRequest(nextMethod, nextUrl, headers, nextBody, opts, redirectCount + 1));
                return;
            }

            const chunks: Buffer[] = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end', () => {
                const responseBody = Buffer.concat(chunks).toString();
                const responseHeaders: Record<string, string | string[]> = {};
                for (const [k, v] of Object.entries(res.headers)) {
                    if (v !== undefined) { responseHeaders[k] = v; }
                }
                resolve({
                    statusCode: res.statusCode || 0,
                    statusMessage: res.statusMessage || '',
                    headers: responseHeaders,
                    body: responseBody
                });
            });
        });

        req.on('timeout', () => { req.destroy(new Error(`Request timed out after ${opts.timeoutMs}ms`)); });
        req.on('error', (e) => reject(e));
        if (body) { req.write(body); }
        req.end();
    });
}

export function parseImports(text: string, baseDir: string, visited: Set<string> = new Set()): { blocks: RequestBlock[]; variables: Record<string, string> } {
    const allBlocks: RequestBlock[] = [];
    const allVars: Record<string, string> = {};
    const importRegex = /^\s*@import\s*=\s*(.+?)\s*$/;

    for (const line of text.split(/\r?\n/)) {
        const match = line.match(importRegex);
        if (!match) { continue; }

        let importPath = match[1];
        if (!path.isAbsolute(importPath)) { importPath = path.join(baseDir, importPath); }
        const absPath = path.resolve(importPath);
        if (visited.has(absPath) || !fs.existsSync(absPath)) { continue; }
        visited.add(absPath);

        const importText = fs.readFileSync(absPath, 'utf8');
        const importDir = path.dirname(absPath);
        const nested = parseImports(importText, importDir, visited);
        Object.assign(allVars, nested.variables);
        allBlocks.push(...nested.blocks);
        Object.assign(allVars, parseFileVariables(importText));
        allBlocks.push(...parseDocumentRequests(importText));
    }

    return { blocks: allBlocks, variables: allVars };
}

export function parseFileVariables(text: string): Record<string, string> {
    const variables: Record<string, string> = {};
    const reserved = new Set(['import', 'env', 'session']);
    const variableRegex = /^\s*@([^\s=]+)\s*=\s*(.+?)\s*$/;

    for (const line of text.split(/\r?\n/)) {
        const match = line.match(variableRegex);
        if (match && !reserved.has(match[1])) {
            variables[match[1]] = match[2];
        }
    }
    return variables;
}

export function substituteVariables(text: string, variables: Record<string, any>): string {
    return text.replace(/\{\{(?:\$env\s+)?([^\s}]+)\}\}/g, (match, variableName) => {
        if (variableName.includes('.')) {
            const parts = variableName.split('.');
            let current = variables;
            for (const part of parts) {
                if (current && typeof current === 'object' && part in current) {
                    current = current[part];
                } else { return match; }
            }
            return String(current);
        }
        if (Object.prototype.hasOwnProperty.call(variables, variableName)) {
            return String(variables[variableName]);
        }
        return match;
    });
}

export function loadEnvFile(rootPath: string, fileName = '.env'): Record<string, string> {
    const envPath = path.join(rootPath, fileName);
    const variables: Record<string, string> = {};

    if (!fs.existsSync(envPath)) { return variables; }
    const content = fs.readFileSync(envPath, 'utf8');

    for (const line of content.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) { continue; }
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0) {
            const key = trimmed.substring(0, eqIndex).trim();
            let value = trimmed.substring(eqIndex + 1).trim();
            if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
                value = value.substring(1, value.length - 1);
            }
            variables[key] = value;
        }
    }
    return variables;
}

function parseTimeout(s: string): number {
    if (!s) { return 0; }
    const match = s.match(/^(\d+)(ms|s|m)?$/);
    if (!match) { return 0; }
    const n = parseInt(match[1], 10);
    switch (match[2]) {
        case 'ms': return n;
        case 'm': return n * 60000;
        default: return n * 1000; // seconds
    }
}

export function deactivate() {}
