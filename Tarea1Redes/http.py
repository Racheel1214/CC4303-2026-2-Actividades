import socket
import json

with open("tarea1.json") as f:
    settings = json.load(f)

USER = settings["user"]
BLOCKED = settings["blocked"]
FORBIDDEN = settings["forbidden_words"]
BUFFER = 50


def parse_HTTP_message(http_message: bytes) -> dict:
    head, _, body = http_message.partition(b"\r\n\r\n")
    lines = head.decode(errors="ignore").split("\r\n")
    first = lines[0].split(" ", 2)

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    if first[0].startswith("HTTP/"):
        return {
            "version": first[0],
            "status_code": first[1],
            "status_text": first[2] if len(first) > 2 else "",
            "headers": headers,
            "body": body,
        }

    return {
        "method": first[0],
        "path": first[1],
        "version": first[2] if len(first) > 2 else "HTTP/1.1",
        "headers": headers,
        "body": body,
    }


def create_HTTP_message(message: dict)->bytes:
    
    if "method" in message:
        start_line = f'{message["method"]} {message["path"]} {message["version"]}'
        
    else:
        start_line = f'{message["version"]} {message["status_code"]} {message["status_text"]}'

    header_lines = [f"{k}: {v}" for k, v in message["headers"].items()]
    
    head = "\r\n".join([start_line] + header_lines) + "\r\n\r\n"

    body = message["body"]
    
    if isinstance(body, str):
        body = body.encode()
    return head.encode() + body


def receive_http_message(sock):
    data = b""
    content_length = 0
    headers_done = False

    while True:
        chunk=sock.recv(BUFFER)
        if not chunk:
            break
        data+=chunk

        if not headers_done and b"\r\n\r\n" in data:
            headers_done = True
            head = data.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
            
            for line in head.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())

        if headers_done:
            body = data.split(b"\r\n\r\n", 1)[1]
            if len(body) >= content_length:
                break

    return data


def build_forbidden_response():
    body = (
        '<html><body><h1>403 Forbidden</h1>'
        '<p>Sitio bloqueado por el proxy</p>'
        '<img src="/yona.jpg"></body></html>'
    )
    return create_HTTP_message({
        "version": "HTTP/1.1",
        "status_code": "403",
        "status_text": "Forbidden",
        "headers": {"Content-Type": "text/html", "Content-Length": str(len(body)), "Connection": "close"},
        "body": body,
    })


def handle_client(client_socket):
    raw_request = receive_http_message(client_socket)
    
    if not raw_request:
        client_socket.close()
        return

    request = parse_HTTP_message(raw_request)

    path = request["path"]
    
    if path.startswith("http://"):
        path = path[len("http://"):]
        host_port, _, resource = path.partition("/")
        resource="/"+resource
        
    else:
        host_port=request["headers"].get("Host", "")
        resource=path

    if ":" in host_port:
        host, port = host_port.split(":")
        port=int(port)
    else:
        host, port = host_port, 80

    if resource == "/yona.jpg":
        with open("yona.jpg", "rb") as f:
            image = f.read()
        client_socket.sendall(create_HTTP_message({
            
            "version": "HTTP/1.1", "status_code": "200", "status_text": "OK",
            "headers": {"Content-Type": "image/jpeg", "Content-Length": str(len(image)), "Connection": "close"},
            "body": image,
        }))
        
        client_socket.close()
        return

    target = (host + resource).rstrip("/")
    blocked_clean = [b[len("http://"):] if b.startswith("http://") else b for b in BLOCKED]
    blocked_clean = [b.rstrip("/") for b in blocked_clean]
    
    
    if any(host == b or target == b or target.startswith(b + "/") for b in blocked_clean):
        client_socket.sendall(build_forbidden_response())
        client_socket.close()
        return

    request["path"] = resource
    request["headers"]["X-ElQuePregunta"] = USER
    request["headers"]["Connection"] = "close"
    request["headers"].pop("Proxy-Connection", None)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, port))
    server_socket.sendall(create_HTTP_message(request))
    raw_response = receive_http_message(server_socket)
    server_socket.close()

    response = parse_HTTP_message(raw_response)
    if response["headers"].get("Content-Type", "").startswith("text/html"):
        body = response["body"].decode(errors="ignore")
        
        for rule in FORBIDDEN:
            for word, replacement in rule.items():
                body = body.replace(word, replacement)
        response["body"] = body
        response["headers"]["Content-Length"] = str(len(body.encode()))

    client_socket.sendall(create_HTTP_message(response))
    client_socket.close()


if __name__ == "__main__":
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind(("0.0.0.0", 8000))
    proxy_socket.listen(5)
    print("Proxy escuchando en 0.0.0.0:8000")

    while True:
        client_socket, addr = proxy_socket.accept()
        print("Conexión de", addr)
        handle_client(client_socket)