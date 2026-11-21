"""Fake 3rd-party telemetry sink for the live demo — accepts anything, 200s."""
import http.server
import os

PORT = int(os.environ.get("SINK_PORT", "9900"))


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"sink on :{PORT}")
    http.server.HTTPServer(("127.0.0.1", PORT), H).serve_forever()
