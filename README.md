# @kinde-oss/mastra-auth-kinde

A [Kinde](https://kinde.com) authentication provider for the [Mastra](https://mastra.ai) AI agent framework, enabling Kinde authentication and organization-based access control in your Mastra applications.

- Kinde authentication integration
- Organization-based access control via `allowedOrgCodes`
- JWT verification using Kinde's JWKS
- M2M / system-actor support for background workflows, cron jobs, and agent pipelines
- Edge-native via `jose`, no `nodejs_compat` flag required on Cloudflare Workers

## Installation

```sh
npm install @kinde-oss/mastra-auth-kinde
# or
yarn add @kinde-oss/mastra-auth-kinde
# or
pnpm add @kinde-oss/mastra-auth-kinde
```

Peer dependencies: `@mastra/core >=1.32.0` and `hono ^4.0.0`, already present in any Mastra app.

## Usage

```typescript
import { Mastra } from '@mastra/core/mastra';
import { MastraAuthKinde } from '@kinde-oss/mastra-auth-kinde';

const auth = new MastraAuthKinde({
  domain: 'https://yourapp.kinde.com',
});

const mastra = new Mastra({
  server: {
    auth,
  },
});
```

The provider reads from environment variables when constructor options are omitted:

```dotenv
KINDE_DOMAIN=https://yourapp.kinde.com
KINDE_AUDIENCE=https://api.yourapp.com
```

`KINDE_AUDIENCE` is optional, see [Audience](#audience).

## Configuration

| Option | Env var | Required | Description |
|---|---|---|---|
| `domain` | `KINDE_DOMAIN` | Yes | Your Kinde tenant URL, e.g. `https://yourapp.kinde.com` |
| `audience` | `KINDE_AUDIENCE` | No | API audience to enforce on the token's `aud` claim |
| `allowedOrgCodes` | — | No | Restrict access to specific Kinde organizations |
| `name` | — | No | Override the provider name (default: `"kinde"`) |

## Methods

`MastraAuthKinde` verifies who the user is and defers what they can do to your own authorization logic.

Mastra invokes `authenticateToken` and `authorizeUser` internally through the `server.auth` integration, so you typically do not call them directly. Their signatures are documented below for reference.

### `authenticateToken(token: string, request: HonoRequest)`

Verifies a Kinde JWT against Kinde's JWKS and returns the decoded user if valid. Supports both user access tokens and M2M tokens.

### `authorizeUser(user: KindeUser, request: HonoRequest)`

Returns whether an authenticated user is allowed access. When `allowedOrgCodes` is set, the user's `org_code` must be in the list.

## Audience

Only set `audience` once you have registered and bound an API audience in the Kinde dashboard. A default Kinde token carries an empty `aud` array, so any token with an empty `aud` will fail the audience check if this option is set.

## Organization-based access control

Pass `allowedOrgCodes` to restrict access to specific Kinde organizations. The check applies to both user tokens and M2M tokens that carry an `org_code` claim:

```typescript
const auth = new MastraAuthKinde({
  domain: 'https://yourapp.kinde.com',
  allowedOrgCodes: ['org_abc123', 'org_def456'],
});
```

## M2M / system-actor support

M2M tokens issued via the OAuth `client_credentials` flow are fully supported. They are identified by the presence of `gty: ["client_credentials"]` and the absence of a `sub` claim. The provider treats them as trusted system actors, which is useful for background workflows, cron jobs, and agent pipelines that need authenticated API access with no human user present.

```typescript
import { isSystemActor } from '@kinde-oss/mastra-auth-kinde';

const user = requestContext.get('user');
if (isSystemActor(user)) {
  // trusted background process
}
```

## Token claims

User access token (human login):
`iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `jti`, `scp`

M2M token (client credentials):
`iss`, `aud`, `azp`, `exp`, `iat`, `jti`, `gty`, `org_code`, `scope`, `scp`, `v`, no `sub`

The optional claims `org_code`, `permissions`, `feature_flags`, and `roles` on user tokens only appear when explicitly enabled in the Kinde dashboard.

## Publishing

The core team handles publishing.

## Contributing

Please refer to Kinde's [contributing guidelines](https://github.com/kinde-oss/.github/blob/main/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
