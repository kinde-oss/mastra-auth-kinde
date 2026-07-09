import { MastraAuthProvider } from '@mastra/core/server';
import type { MastraAuthProviderOptions } from '@mastra/core/server';
import type { HonoRequest } from 'hono';
import { createRemoteJWKSet, jwtVerify } from 'jose';

/**
 * Claims confirmed from real decoded Kinde tokens (both user and M2M).
 *
 * Required fields are present in every token type.
 * `sub` is absent in M2M (client_credentials) tokens — use isSystemActor()
 * to distinguish M2M callers.
 *
 * Optional fields marked "Kinde-config-dependent" only appear when explicitly
 * enabled in the Kinde dashboard and are absent from default tokens.
 */
export interface KindeUser {
  // Confirmed present in both user and M2M tokens
  iss: string;
  /** Present in user tokens; absent in M2M (client_credentials) tokens. */
  sub?: string;
  /** Empty array on a default user token; kept permissive to match aud normalization. */
  aud: string | string[];
  /** Authorized party — the client ID of the application that requested the token. */
  azp: string;
  exp: number;
  iat: number;
  jti: string;
  /** Scopes as an array. Empty array in M2M tokens (use scope for the string form). */
  scp: string[];
  // Confirmed present in M2M (client_credentials) tokens
  /** Grant type — e.g. ["client_credentials"] in M2M tokens. */
  gty?: string[];
  /** Space-delimited scopes string — present in M2M tokens. */
  scope?: string;
  /** Token version string — present in M2M tokens. */
  v?: string;
  // Kinde-config-dependent — absent from default tokens
  org_code?: string;
  permissions?: string[];
  feature_flags?: Record<string, unknown>;
  /** Shape unconfirmed; not present in a default token. */
  roles?: unknown[];
  [key: string]: unknown;
}

export interface MastraAuthKindeOptions extends MastraAuthProviderOptions<KindeUser> {
  /**
   * Your full Kinde domain, e.g. https://yourapp.kinde.com
   * Falls back to process.env.KINDE_DOMAIN.
   */
  domain?: string;
  /**
   * The API audience registered in your Kinde dashboard.
   * Falls back to process.env.KINDE_AUDIENCE.
   * When set, every token's aud claim must include this value.
   */
  audience?: string;
  /**
   * When set and non-empty, only tokens whose org_code is in this list are
   * authorized. Applies to both user and M2M tokens.
   */
  allowedOrgCodes?: string[];
}

/**
 * Returns true when the token was issued via a machine-to-machine
 * client_credentials grant (no human subject).
 */
export function isSystemActor(user: KindeUser): boolean {
  return Array.isArray(user?.gty) && user.gty.includes('client_credentials');
}

export class MastraAuthKinde extends MastraAuthProvider<KindeUser> {
  private readonly issuer: string;
  private readonly audience: string | undefined;
  private readonly allowedOrgCodes: string[] | undefined;
  // Built once per instance; jose caches the fetched key set internally.
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(options?: MastraAuthKindeOptions) {
    super({ name: options?.name ?? 'kinde' });

    const domain = options?.domain ?? process.env['KINDE_DOMAIN'];
    const audience = options?.audience ?? process.env['KINDE_AUDIENCE'];

    if (!domain) {
      throw new Error(
        'Kinde domain is required. Provide it via options.domain or the KINDE_DOMAIN environment variable.',
      );
    }

    // Kinde JWKS path confirmed from /.well-known/openid-configuration
    // (jwks_uri field). The path has no .json extension.
    const jwksUri = `${domain}/.well-known/jwks`;
    this.issuer = domain;
    this.audience = audience || undefined;
    this.allowedOrgCodes = options?.allowedOrgCodes?.length ? options.allowedOrgCodes : undefined;
    this.jwks = createRemoteJWKSet(new URL(jwksUri));

    this.registerOptions(options);
  }

  async authenticateToken(token: string, _request: HonoRequest): Promise<KindeUser | null> {
    if (!token) return null;

    try {
      // jose validates signature, issuer, exp, nbf, and audience (when provided)
      // automatically — no manual claim checks needed.
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        ...(this.audience ? { audience: this.audience } : {}),
      });
      return payload as unknown as KindeUser;
    } catch {
      return null;
    }
  }

  authorizeUser(user: KindeUser, _request: HonoRequest): boolean {
    const isUser = !!user?.sub;
    const isM2M = isSystemActor(user);

    if (!isUser && !isM2M) return false;

    if (this.allowedOrgCodes) {
      if (!user.org_code || !this.allowedOrgCodes.includes(user.org_code)) return false;
    }

    return true;
    // TODO: add permissions / roles checks once claim shapes are confirmed
  }
}
