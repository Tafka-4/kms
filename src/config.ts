import fs from "node:fs";
import path from "node:path";

const DEFAULT_PORT = 3000;
const DEFAULT_WHITELIST = "127.0.0.1/32,10.64.0.0/24,172.18.0.0/24";
const DEFAULT_KEY_STORE = "./data/keys";
const DEFAULT_CRYPTO_PLAINTEXT_BYTES = 10 * 1024 * 1024; // 10MB
const MAX_CRYPTO_PLAINTEXT_BYTES = 64 * 1024 * 1024; // cap to protect the KMS

export type AppConfig = {
	port: number;
	whitelist: string[];
	keyStorePath: string;
	nodeEnv: string | undefined;
	sessionTtlMs: number;
	sessionSliding: boolean;
	rotateRateLimitWindowMs: number;
	rotateRateLimitMax: number;
	tokenPrefix?: string;
	cryptoRateLimitWindowMs: number;
	cryptoRateLimitMax: number;
	cryptoPlaintextLimitBytes: number;
	keysRateLimitWindowMs: number;
	keysRateLimitMax: number;
};

export function loadConfig(): AppConfig {
	const port = Number(process.env.KMS_PORT ?? DEFAULT_PORT);
	const whitelistCsv = (
		process.env.KMS_WHITELIST ?? DEFAULT_WHITELIST
	).trim();
	const whitelist = whitelistCsv
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
	const keyStorePath = process.env.KEY_STORE_PATH ?? DEFAULT_KEY_STORE;
	const nodeEnv = process.env.NODE_ENV;
	const sessionTtlMs = Number(
		process.env.KMS_SESSION_TTL_MS ?? 15 * 60 * 1000
	);
	const sessionSliding =
		String(process.env.KMS_SESSION_SLIDING ?? "true") === "true";
	const rotateRateLimitWindowMs = Number(
		process.env.KMS_ROTATE_WINDOW_MS ?? 10_000
	);
	const rotateRateLimitMax = Number(process.env.KMS_ROTATE_MAX ?? 5);
	const cryptoRateLimitWindowMs = Number(
		process.env.KMS_CRYPTO_WINDOW_MS ?? 10_000
	);
	const cryptoRateLimitMax = Number(process.env.KMS_CRYPTO_MAX ?? 50);
	const cryptoPlaintextLimitEnv = Number(
		process.env.KMS_CRYPTO_MAX_PLAINTEXT_BYTES ??
			process.env.KMS_CRYPTO_PLAINTEXT_BYTES ??
			DEFAULT_CRYPTO_PLAINTEXT_BYTES
	);
	const cryptoPlaintextLimitBytes =
		Number.isFinite(cryptoPlaintextLimitEnv) && cryptoPlaintextLimitEnv > 0
			? Math.min(
					cryptoPlaintextLimitEnv,
					MAX_CRYPTO_PLAINTEXT_BYTES
			  )
			: DEFAULT_CRYPTO_PLAINTEXT_BYTES;
	const keysRateLimitWindowMs = Number(
		process.env.KMS_KEYS_WINDOW_MS ?? 10_000
	);
	const keysRateLimitMax = Number(process.env.KMS_KEYS_MAX ?? 20);
	const tokenPrefix = process.env.KMS_TOKEN_PREFIX?.trim() || undefined;

	ensureKeyStorePath(keyStorePath);

	return {
		port,
		whitelist,
		keyStorePath,
		nodeEnv,
		sessionTtlMs,
		sessionSliding,
		rotateRateLimitWindowMs,
		rotateRateLimitMax,
		tokenPrefix,
		cryptoRateLimitWindowMs,
		cryptoRateLimitMax,
		cryptoPlaintextLimitBytes,
		keysRateLimitWindowMs,
		keysRateLimitMax,
	};
}

function ensureKeyStorePath(dir: string) {
	try {
		if (!fs.existsSync(dir)) {
			fs.mkdirSync(dir, { recursive: true });
		}
		// test write permissions via temp file
		const testFile = path.join(dir, `.write-test-${Date.now()}`);
		fs.writeFileSync(testFile, "ok");
		fs.rmSync(testFile);
	} catch (err) {
		// eslint-disable-next-line no-console
		console.error(
			JSON.stringify(
				{
					error: {
						code: "CONFIG_KEY_STORE_PATH",
						message: `KEY_STORE_PATH not writeable: ${dir}`,
						details: String(err),
					},
				},
				null,
				2
			)
		);
		process.exit(1);
	}
}
