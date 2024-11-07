declare global {
  interface Env {
    ai_proxy: KVNamespace;
    BRAINTRUST_APP_URL: string;
    DISABLE_METRICS?: boolean;
    PROMETHEUS_SCRAPE_USER?: string;
    PROMETHEUS_SCRAPE_PASSWORD?: string;
    WHITELISTED_ORIGINS?: string;

    OPENAI_API_KEY: string;
    ANTHROPIC_API_KEY: string;
    GOOGLE_API_KEY: string;
    MISTRAL_API_KEY: string;
    PERPLEXITY_API_KEY: string;
    AZURE_API_KEY: string;
    REPLICATE_API_KEY: string;
    TOGETHER_API_KEY: string;
    LEPTON_API_KEY: string;
    FIREWORKS_API_KEY: string;
    CEREBRAS_API_KEY: string;
    GROQ_API_KEY: string;
    XAI_API_KEY: string;
    OLLAMA_API_KEY: string;
  }
}

export function braintrustAppUrl(env: Env) {
  return new URL(env.BRAINTRUST_APP_URL || "https://www.braintrust.dev");
}
