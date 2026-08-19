import { handleApiRequest } from "../functions/api/[[route]]";

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
      return handleApiRequest(request, env, route);
    }
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
