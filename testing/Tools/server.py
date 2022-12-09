import socket
import struct

def bad_backend():
    # Ready for query, but somehow broken.
    return b"Z\x00\x00\x00\x01\x00\x00"

def good_error():
    typ = b"E"
    code1 = b"S"
    message1 = b"INFO\x00"
    code2 = b"M"
    message2 = b"Test Error\x00"
    end = b"\x00"

    length = struct.pack("!l", len(typ) + len(code1) + len(message1) + len(code2) + len(message2) + len(end))
    return typ + length + code1 + message1 + code2 + message2 + end;



def handle_client(s):
    while True:
        b = s.recv(1024)
        if not b:
            break

        print("got", b)

        if b[:4] == b"\x00\x00\x00\x03":
            print("sending good error")
            s.send(good_error())
        else:
            print("sending bad error")
            s.send(bad_backend())



s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(("127.0.0.1", 5432))
s.listen()

while True:
    c, addr = s.accept()
    print(c, addr)
    handle_client(c)
    c.close()
