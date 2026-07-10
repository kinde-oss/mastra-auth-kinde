import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock jose before importing the provider so vi.mock hoisting works.
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => 'dummy-jwks-set'),
  jwtVerify: vi.fn(),
}));

import { createRemoteJWKSet, jwtVerify } from 'jose';
import { MastraAuthKinde, isSystemActor } from '../src/index.js';
import type { KindeUser } from '../src/index.js';

const mockCreateRemoteJWKSet = vi.mocked(createRemoteJWKSet);
const mockJwtVerify = vi.mocked(jwtVerify);

const DOMAIN = 'https://example.kinde.com';

function validPayload(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: DOMAIN,
    sub: 'kp:user_01234567890',
    aud: ['https://api.example.com'],
    azp: 'client_123',
    exp: now + 3600,
    iat: now,
    jti: 'jti_user_123',
    scp: [],
    ...overrides,
  };
}

function m2mPayload(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: DOMAIN,
    aud: ['https://api.example.com'],
    azp: 'm2m_client_id',
    exp: now + 3600,
    iat: now,
    jti: 'jti_m2m_123',
    gty: ['client_credentials'],
    org_code: 'org_test',
    scope: 'read:data write:data',
    scp: [],
    v: '1',
    // no sub — mirrors real M2M token shape
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env['KINDE_DOMAIN'];
  delete process.env['KINDE_AUDIENCE'];
});

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe('constructor', () => {
  it('throws when domain is missing from both options and env', () => {
    expect(() => new MastraAuthKinde()).toThrow(
      'Kinde domain is required',
    );
  });

  it('reads domain from KINDE_DOMAIN env var', () => {
    process.env['KINDE_DOMAIN'] = DOMAIN;
    expect(() => new MastraAuthKinde()).not.toThrow();
  });

  it('uses the name option when provided', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN, name: 'my-kinde' });
    // The name is stored internally; checking it doesn't throw and constructs.
    expect(provider).toBeInstanceOf(MastraAuthKinde);
  });

  it('defaults provider name to "kinde"', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    expect(provider).toBeInstanceOf(MastraAuthKinde);
  });

  it('builds the JWKS URL from the domain (path is /.well-known/jwks, no .json)', () => {
    new MastraAuthKinde({ domain: DOMAIN });
    expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
      new URL(`${DOMAIN}/.well-known/jwks`),
    );
  });

  it('normalizes a trailing slash on the domain for the JWKS URL', () => {
    new MastraAuthKinde({ domain: 'https://example.kinde.com/' });
    expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
      new URL('https://example.kinde.com/.well-known/jwks'),
    );
  });

  it('normalizes a trailing slash on the domain for the issuer', async () => {
    const provider = new MastraAuthKinde({ domain: 'https://example.kinde.com/' });
    mockJwtVerify.mockResolvedValueOnce({ payload: validPayload() } as any);

    await provider.authenticateToken(
      'token',
      {} as Parameters<MastraAuthKinde['authenticateToken']>[1],
    );

    expect(mockJwtVerify).toHaveBeenCalledWith(
      'token',
      'dummy-jwks-set',
      expect.objectContaining({ issuer: 'https://example.kinde.com' }),
    );
  });
});

// ---------------------------------------------------------------------------
// authenticateToken
// ---------------------------------------------------------------------------

describe('authenticateToken', () => {
  const fakeRequest = {} as Parameters<MastraAuthKinde['authenticateToken']>[1];

  it('returns the user payload when jwtVerify resolves', async () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    mockJwtVerify.mockResolvedValueOnce({ payload: validPayload() } as any);

    const result = await provider.authenticateToken('valid.jwt.token', fakeRequest);

    expect(result).not.toBeNull();
    expect(result?.sub).toBe('kp:user_01234567890');
  });

  it('passes the pre-built JWKS set to jwtVerify', async () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    mockJwtVerify.mockResolvedValueOnce({ payload: validPayload() } as any);

    await provider.authenticateToken('valid.jwt.token', fakeRequest);

    // First arg = token, second = the jwks set built in the constructor
    expect(mockJwtVerify).toHaveBeenCalledWith(
      'valid.jwt.token',
      'dummy-jwks-set',
      expect.objectContaining({ issuer: DOMAIN }),
    );
  });

  it('returns null when jwtVerify throws (invalid signature, expired, wrong issuer, etc.)', async () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    mockJwtVerify.mockRejectedValueOnce(new Error('JWSSignatureVerificationFailed'));

    const result = await provider.authenticateToken('bad.jwt.token', fakeRequest);

    expect(result).toBeNull();
  });

  it('returns null for an empty token without calling jwtVerify', async () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });

    const result = await provider.authenticateToken('', fakeRequest);

    expect(result).toBeNull();
    expect(mockJwtVerify).not.toHaveBeenCalled();
  });

  it('passes audience to jwtVerify when audience option is set', async () => {
    const provider = new MastraAuthKinde({
      domain: DOMAIN,
      audience: 'https://api.example.com',
    });
    mockJwtVerify.mockResolvedValueOnce({ payload: validPayload() } as any);

    await provider.authenticateToken('token', fakeRequest);

    expect(mockJwtVerify).toHaveBeenCalledWith(
      'token',
      'dummy-jwks-set',
      expect.objectContaining({ audience: 'https://api.example.com' }),
    );
  });

  it('omits audience from jwtVerify when no audience option is set', async () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    mockJwtVerify.mockResolvedValueOnce({ payload: validPayload() } as any);

    await provider.authenticateToken('token', fakeRequest);

    const callOptions = mockJwtVerify.mock.calls[0]?.[2] as Record<string, unknown>;
    expect(callOptions).not.toHaveProperty('audience');
  });

  it('reads audience from KINDE_AUDIENCE env var and passes it to jwtVerify', async () => {
    process.env['KINDE_AUDIENCE'] = 'https://env-api.example.com';
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    mockJwtVerify.mockResolvedValueOnce({ payload: validPayload() } as any);

    await provider.authenticateToken('token', fakeRequest);

    expect(mockJwtVerify).toHaveBeenCalledWith(
      'token',
      'dummy-jwks-set',
      expect.objectContaining({ audience: 'https://env-api.example.com' }),
    );
  });
});

// ---------------------------------------------------------------------------
// isSystemActor
// ---------------------------------------------------------------------------

describe('isSystemActor', () => {
  it('returns true for a client_credentials token with no sub', () => {
    expect(isSystemActor(m2mPayload())).toBe(true);
  });

  it('returns false for a client_credentials token that also has a sub', () => {
    expect(isSystemActor(m2mPayload({ sub: 'kp:user_123' }))).toBe(false);
  });

  it('returns false for a user token (sub, no gty)', () => {
    expect(isSystemActor(validPayload())).toBe(false);
  });

  it('returns false when neither gty nor sub is present', () => {
    const user: KindeUser = { iss: DOMAIN, aud: [], azp: 'app', exp: 0, iat: 0, jti: 'x', scp: [] };
    expect(isSystemActor(user)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// authorizeUser
// ---------------------------------------------------------------------------

describe('authorizeUser', () => {
  const fakeRequest = {} as Parameters<MastraAuthKinde['authorizeUser']>[1];

  it('returns true when user has a sub claim', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });

    expect(provider.authorizeUser(validPayload(), fakeRequest)).toBe(true);
  });

  it('returns false when user has no sub claim', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    const user = { iss: DOMAIN, aud: [], exp: 0, iat: 0 };

    expect(provider.authorizeUser(user as any, fakeRequest)).toBe(false);
  });

  it('returns false when user is null-ish', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });

    expect(provider.authorizeUser(null as any, fakeRequest)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// authorizeUser — M2M (client_credentials) tokens
// ---------------------------------------------------------------------------

describe('authorizeUser — M2M tokens', () => {
  const fakeRequest = {} as Parameters<MastraAuthKinde['authorizeUser']>[1];

  it('returns true for an M2M token (gty contains client_credentials, no sub)', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    expect(provider.authorizeUser(m2mPayload(), fakeRequest)).toBe(true);
  });

  it('returns false when neither sub nor client_credentials gty is present', () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    const user: KindeUser = {
      iss: DOMAIN,
      aud: [],
      azp: 'app',
      exp: 0,
      iat: 0,
      jti: 'x',
      scp: [],
      gty: ['some_other_grant'],
    };
    expect(provider.authorizeUser(user, fakeRequest)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// authorizeUser — allowedOrgCodes
// ---------------------------------------------------------------------------

describe('authorizeUser — allowedOrgCodes', () => {
  const fakeRequest = {} as Parameters<MastraAuthKinde['authorizeUser']>[1];

  it('returns true when user org_code is in allowedOrgCodes', () => {
    const provider = new MastraAuthKinde({
      domain: DOMAIN,
      allowedOrgCodes: ['org_test', 'org_other'],
    });
    const user = validPayload({ org_code: 'org_test' });
    expect(provider.authorizeUser(user, fakeRequest)).toBe(true);
  });

  it('returns false when user org_code is not in allowedOrgCodes', () => {
    const provider = new MastraAuthKinde({
      domain: DOMAIN,
      allowedOrgCodes: ['org_test'],
    });
    const user = validPayload({ org_code: 'org_different' });
    expect(provider.authorizeUser(user, fakeRequest)).toBe(false);
  });

  it('returns false when allowedOrgCodes is set but org_code is absent', () => {
    const provider = new MastraAuthKinde({
      domain: DOMAIN,
      allowedOrgCodes: ['org_test'],
    });
    expect(provider.authorizeUser(validPayload(), fakeRequest)).toBe(false);
  });

  it('returns true for M2M token when org_code is in allowedOrgCodes', () => {
    const provider = new MastraAuthKinde({
      domain: DOMAIN,
      allowedOrgCodes: ['org_test'],
    });
    // m2mPayload() includes org_code: 'org_test'
    expect(provider.authorizeUser(m2mPayload(), fakeRequest)).toBe(true);
  });

  it('returns false for M2M token when org_code is not in allowedOrgCodes', () => {
    const provider = new MastraAuthKinde({
      domain: DOMAIN,
      allowedOrgCodes: ['org_test'],
    });
    expect(
      provider.authorizeUser(m2mPayload({ org_code: 'org_wrong' }), fakeRequest),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// authenticateToken — M2M-shaped token
// ---------------------------------------------------------------------------

describe('authenticateToken — M2M token', () => {
  const fakeRequest = {} as Parameters<MastraAuthKinde['authenticateToken']>[1];

  it('returns the payload for a valid M2M-shaped token (no sub)', async () => {
    const provider = new MastraAuthKinde({ domain: DOMAIN });
    mockJwtVerify.mockResolvedValueOnce({ payload: m2mPayload() } as any);

    const result = await provider.authenticateToken('m2m.jwt.token', fakeRequest);

    expect(result).not.toBeNull();
    expect(result?.sub).toBeUndefined();
    expect(result?.gty).toEqual(['client_credentials']);
    expect(result?.org_code).toBe('org_test');
  });
});
