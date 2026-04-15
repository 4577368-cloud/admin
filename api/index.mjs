// Vercel Serverless Function entrypoint.
// Keep a direct Express app import in the deployed function.
const { default: app } = await import('../admin-server.mjs');

export default function handler(req, res) {
  return app(req, res);
}
