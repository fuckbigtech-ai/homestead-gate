// demo.fuckbigtech.ai -> wherever the homestead demo currently runs.
// The Devpost submission locks on Oct 30, so it links here, not to a host. To move the demo
// (Modal <-> Nebius Serverless), change TARGET and run `npx wrangler deploy` in this folder.
const TARGET = "https://frumza--homestead-web-demo-web.modal.run";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    return Response.redirect(TARGET + url.pathname + url.search, 302);   // 302: browsers don't cache it
  },
};
