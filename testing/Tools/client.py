import socket
import struct

def good_startup():
    version = b"\x00\x03\x00\x00"
    something = b"user\x00zeek\x00"
    end = b"\x00"

    length = struct.pack("!l", 4 + len(version) + len(something) + len(end))
    return length + version + something + end

def bad_startup():
    version = b"\x00\x03\x00\x00"
    something = b"user\x00zeek\x00"
    end = b"\x00"
    return b"\x00\x00\x00\x03" + version + something + end


s = socket.socket()

s.connect(("127.0.0.1", 5432))

__import__('IPython').embed(banner1="")
