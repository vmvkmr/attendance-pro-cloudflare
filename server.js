import http from "node:http";
import worker from "./worker.js";

const port = Number(process.env.PORT || 10000);

const server = http.createServer(async (req, res) => {
  try {
    const host = req.headers.host || `localhost:${port}`;
    const url = `http://${host}${req.url}`;

    const headers = new Headers();

    for (const [key, value] of Object.entries(req.headers)) {
      if (value !== undefined) {
        headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      }
    }

    const chunks = [];

    for await (const chunk of req) {
      chunks.push(chunk);
    }

    const body =
      req.method === "GET" || req.method === "HEAD"
        ? undefined
        : Buffer.concat(chunks);

    const request = new Request(url, {
      method: req.method,
      headers,
      body
    });

    const env = {
      SUPABASE_URL: process.env.SUPABASE_URL,
      SUPABASE_SECRET_KEY: process.env.SUPABASE_SECRET_KEY
    };

    const response = await worker.fetch(request, env, {});

    res.statusCode = response.status;

    response.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });

    const data = Buffer.from(await response.arrayBuffer());
    res.end(data);

  } catch (error) {
    console.error(error);
    res.statusCode = 500;
    res.end("Internal Server Error");
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`Server running on port ${port}`);
});
