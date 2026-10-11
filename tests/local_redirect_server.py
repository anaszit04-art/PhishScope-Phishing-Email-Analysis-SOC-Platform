
from http.server import BaseHTTPRequestHandler, HTTPServer


class RedirectHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/middle")
            self.end_headers()

        elif self.path == "/middle":
            self.send_response(301)
            self.send_header("Location", "/final")
            self.end_headers()

        elif self.path == "/final":
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/plain"
            )
            self.end_headers()
            self.wfile.write(b"Safe final page")

        else:
            self.send_error(404)


if __name__ == "__main__":
    server = HTTPServer(
        ("127.0.0.1", 8080),
        RedirectHandler
    )

    print("Server running on 127.0.0.1:8080")
    server.serve_forever()
