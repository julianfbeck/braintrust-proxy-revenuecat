import { DEFAULT_BRAINTRUST_APP_URL } from "@lib/constants";
import { flushMetrics } from "@lib/metrics";
import { proxyV1 } from "@lib/proxy";
import { isEmpty } from "@lib/util";
import { MeterProvider } from "@opentelemetry/sdk-metrics";

import { APISecret, getModelEndpointTypes } from "@schema";
import { verifyTempCredentials, isTempCredential } from "utils";
import {
  decryptMessage,
  EncryptedMessage,
  encryptMessage,
} from "utils/encrypt";

export { FlushingExporter } from "./exporter";

export interface EdgeContext {
  waitUntil(promise: Promise<any>): void;
}

export interface CacheSetOptions {
  ttl?: number;
}
export interface Cache {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, options?: { ttl?: number }): Promise<void>;
}

export interface ProxyOpts {
  getRelativeURL(request: Request): string;
  cors?: boolean;
  credentialsCache?: Cache;
  completionsCache?: Cache;
  braintrustApiUrl?: string;
  meterProvider?: MeterProvider;
  whitelist?: (string | RegExp)[];
  apiKeys?: {
    openai?: string;
    anthropic?: string;
    google?: string;
    mistral?: string;
    perplexity?: string;
    azure?: string;
    replicate?: string;
    together?: string;
    lepton?: string;
    fireworks?: string;
    cerebras?: string;
    groq?: string;
    xAI?: string;
    ollama?: string;
  };
}

const defaultWhitelist: (string | RegExp)[] = [
  "https://www.braintrustdata.com",
  "https://www.braintrust.dev",
  new RegExp("https://.*-braintrustdata.vercel.app"),
  new RegExp("https://.*.preview.braintrust.dev"),
];

const baseCorsHeaders = {
  "access-control-allow-credentials": "true",
  "access-control-allow-methods": "GET,OPTIONS,POST",
};

export function getCorsHeaders(
  request: Request,
  whitelist: (string | RegExp)[] | undefined
) {
  whitelist = whitelist || defaultWhitelist;

  // If the host is not in the whitelist, return a 403.
  const origin = request.headers.get("Origin");
  if (
    origin &&
    !whitelist.some(
      (w) => w === origin || (w instanceof RegExp && w.test(origin))
    )
  ) {
    throw new Error("Forbidden");
  }

  return origin
    ? {
        "access-control-allow-origin": origin,
        ...baseCorsHeaders,
      }
    : {};
}

// https://developers.cloudflare.com/workers/examples/cors-header-proxy/
async function handleOptions(
  request: Request,
  corsHeaders: Record<string, string>
) {
  if (
    request.headers.get("Origin") !== null &&
    request.headers.get("Access-Control-Request-Method") !== null &&
    request.headers.get("Access-Control-Request-Headers") !== null
  ) {
    // Handle CORS preflight requests.
    return new Response(null, {
      headers: {
        ...corsHeaders,
        "access-control-allow-headers": request.headers.get(
          "Access-Control-Request-Headers"
        )!,
      },
    });
  } else {
    // Handle standard OPTIONS request.
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS",
      },
    });
  }
}

export async function digestMessage(message: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

export function makeFetchApiSecrets({
  ctx,
  opts,
}: {
  ctx: EdgeContext;
  opts: ProxyOpts;
}) {
  return async (
    useCache: boolean,
    authToken: string,
    model: string | null,
    org_name?: string
  ): Promise<APISecret[]> => {
    const endpointTypes = model ? getModelEndpointTypes(model) : [];
    const endpointType = endpointTypes[0] || "openai";

    switch (endpointType) {
      case "openai":
        return [
          {
            secret: opts.apiKeys?.openai || "secret not set in proxy",
            type: "openai",
          },
        ];

      case "anthropic":
        return [
          {
            secret: opts.apiKeys?.anthropic || "secret not set in proxy",
            type: "anthropic",
          },
        ];

      case "google":
        return [
          {
            secret: opts.apiKeys?.google || "secret not set in proxy",
            type: "google",
          },
        ];

      case "mistral":
        return [
          {
            secret: opts.apiKeys?.mistral || "secret not set in proxy",
            type: "mistral",
          },
        ];

      case "perplexity":
        return [
          {
            secret: opts.apiKeys?.perplexity || "secret not set in proxy",
            type: "perplexity",
          },
        ];

      case "azure":
        return [
          {
            secret: opts.apiKeys?.azure || "secret not set in proxy",
            type: "azure",
          },
        ];

      case "replicate":
        return [
          {
            secret: opts.apiKeys?.replicate || "secret not set in proxy",
            type: "replicate",
          },
        ];

      case "together":
        return [
          {
            secret: opts.apiKeys?.together || "secret not set in proxy",
            type: "together",
          },
        ];

      case "lepton":
        return [
          {
            secret: opts.apiKeys?.lepton || "secret not set in proxy",
            type: "lepton",
          },
        ];

      case "fireworks":
        return [
          {
            secret: opts.apiKeys?.fireworks || "secret not set in proxy",
            type: "fireworks",
          },
        ];

      case "cerebras":
        return [
          {
            secret: opts.apiKeys?.cerebras || "secret not set in proxy",
            type: "cerebras",
          },
        ];

      case "groq":
        return [
          {
            secret: opts.apiKeys?.groq || "secret not set in proxy",
            type: "groq",
          },
        ];

      case "xAI":
        return [
          {
            secret: opts.apiKeys?.xAI || "secret not set in proxy",
            type: "xAI",
          },
        ];

      case "ollama":
        return [
          {
            secret: opts.apiKeys?.ollama || "secret not set in proxy",
            type: "ollama",
          },
        ];

      default:
        return [
          {
            secret: opts.apiKeys?.openai || "secret not set in proxy",
            type: "openai",
          },
        ];
    }
  };
}

export function EdgeProxyV1(opts: ProxyOpts) {
  const meterProvider = opts.meterProvider;
  return async (request: Request, ctx: EdgeContext) => {
    let corsHeaders = {};
    try {
      if (opts.cors) {
        corsHeaders = getCorsHeaders(request, opts.whitelist);
      }
    } catch (e) {
      return new Response("Forbidden", { status: 403 });
    }

    if (request.method === "OPTIONS" && opts.cors) {
      return handleOptions(request, corsHeaders);
    }
    if (request.method !== "GET" && request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { "Content-Type": "text/plain" },
      });
    }

    const relativeURL = opts.getRelativeURL(request);

    // Create an identity TransformStream (a.k.a. a pipe).
    // The readable side will become our new response body.
    let { readable, writable } = new TransformStream();

    let status = 200;

    let headers: Record<string, string> = opts.cors ? corsHeaders : {};

    const setStatus = (code: number) => {
      status = code;
    };
    const setHeader = (name: string, value: string) => {
      headers[name] = value;
    };

    const proxyHeaders: Record<string, string> = {};
    request.headers.forEach((value, name) => {
      proxyHeaders[name] = value;
    });

    const cacheGet = async (encryptionKey: string, key: string) => {
      if (opts.completionsCache) {
        return (
          (await encryptedGet(opts.completionsCache, encryptionKey, key)) ??
          null
        );
      } else {
        return null;
      }
    };

    const fetchApiSecrets = makeFetchApiSecrets({ ctx, opts });

    const cachePut = async (
      encryptionKey: string,
      key: string,
      value: string,
      ttl_seconds?: number
    ): Promise<void> => {
      if (opts.completionsCache) {
        const ret = encryptedPut(
          opts.completionsCache,
          encryptionKey,
          key,
          value,
          {
            // 1 week if not specified
            ttl: ttl_seconds ?? 60 * 60 * 24 * 7,
          }
        );
        ctx.waitUntil(ret);
        return ret;
      }
    };

    try {
      await proxyV1({
        method: request.method,
        url: relativeURL,
        proxyHeaders,
        body: await request.text(),
        setHeader,
        setStatusCode: setStatus,
        res: writable,
        getApiSecrets: fetchApiSecrets,
        cacheGet,
        cachePut,
        digest: digestMessage,
        meterProvider,
      });
    } catch (e) {
      return new Response(`${e}`, {
        status: 400,
        headers: { "Content-Type": "text/plain" },
      });
    } finally {
      if (meterProvider) {
        ctx.waitUntil(flushMetrics(meterProvider));
      }
    }

    return new Response(readable, {
      status,
      headers,
    });
  };
}

// We rely on the fact that Upstash will automatically serialize and deserialize things for us
export async function encryptedGet(
  cache: Cache,
  encryptionKey: string,
  key: string
) {
  const message = await cache.get<EncryptedMessage>(key);
  if (isEmpty(message)) {
    return null;
  }

  return await decryptMessage(encryptionKey, message.iv, message.data);
}

async function encryptedPut(
  cache: Cache,
  encryptionKey: string,
  key: string,
  value: string,
  options?: { ttl?: number }
) {
  options = options || {};

  const encryptedValue = await encryptMessage(encryptionKey, value);
  await cache.set(key, encryptedValue, options);
}
