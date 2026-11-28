# TomOS POS web interface

Next.js management interface for the Rust/Axum API.

## Development

Requires Node.js 22 or newer and npm.

```sh
cd frontend/web
npm install
npm run dev
```

The browser calls the API through same-origin `/api/v1` paths. Configure the deployment reverse proxy to forward `/api/v1/*` to Axum and serve Next.js on the same origin. This preserves the HttpOnly session cookie and exact-Origin checks without exposing session tokens to JavaScript.

The initial interface covers login, tenant discovery, business selection and settings, locations, staff invitations and membership removal, and custom role creation. Invitation tokens are returned once and must be delivered manually over a secure channel.

This is not yet an installable/offline PWA or a checkout client. Do not use it for live payment processing.
