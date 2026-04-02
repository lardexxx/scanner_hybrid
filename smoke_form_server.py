from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs


HOST = "127.0.0.1"
PORT = 8765


FORM_HTML = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Smoke Form</title>
  </head>
  <body>
    <h1>Smoke Form</h1>
    <form action="/submit" method="POST">
      <input type="hidden" name="csrf_token" value="">
      <input type="text" name="q" value="hello">
      <button type="submit" name="action" value="search">Search</button>
    </form>
    <script>
      const token = document.querySelector('input[name="csrf_token"]');
      if (token) token.value = "JS123TOKEN";
    </script>
  </body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return

        body = FORM_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/submit":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        data = parse_qs(raw, keep_blank_values=True)

        token = data.get("csrf_token", [""])[0]
        action = data.get("action", [""])[0]
        query = data.get("q", [""])[0]

        if token != "JS123TOKEN" or action != "search":
            body = (
                "<html><body><h1>Rejected</h1>"
                "<p>token/action mismatch</p>"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = (
            "<html><body>"
            "<h1>Search Result</h1>"
            f"<div id='echo'>{query}</div>"
            "</body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Smoke form server listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
