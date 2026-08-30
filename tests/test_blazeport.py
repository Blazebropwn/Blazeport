import socket
import threading

from blazeport import save_results, scan_port


def test_scans_local_server_and_sends_http_probe():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        connection, _ = server.accept()
        with connection:
            request = connection.recv(1024)
            assert request.startswith(b"HEAD / HTTP/1.0")
            connection.sendall(b"HTTP/1.0 200 OK\r\nServer: test\r\n\r\n")
        server.close()

    worker = threading.Thread(target=serve)
    worker.start()
    result = scan_port("localhost", "127.0.0.1", port, 1.0, "http")
    worker.join(timeout=2)
    assert result is not None
    assert result.port == port
    assert "200 OK" in result.banner


def test_closed_port_returns_none():
    temporary = socket.socket()
    temporary.bind(("127.0.0.1", 0))
    port = temporary.getsockname()[1]
    temporary.close()
    assert scan_port("localhost", "127.0.0.1", port, 0.1, "none") is None


def test_exports_txt_and_csv(tmp_path):
    txt, csv = save_results([], str(tmp_path / "scan"))
    assert txt.read_text().startswith("BlazePort scan results")
    assert csv.read_text().startswith("Host,IP,Port,Service,Banner")
