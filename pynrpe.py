# coding: utf-8
#
# CopyWTF (c) 2013, Stiletto <blasux@blasux.ru>
# Go read the fucking COPYING for fuck's sake
#

__all__ = [ 'NRPE_REQUEST', 'NRPE_RESPONSE', 'NRPE_OK', 'NRPE_WARNING',
            'NRPE_CRITICAL', 'NRPE_UNKNOWN', 'PACKET_SIZE', 'create_request',
            'parse_response', 'check_nrpe' ]

import struct, binascii, socket, ssl

NRPE_REQUEST = 1
NRPE_RESPONSE = 2

NRPE_OK = 0
NRPE_WARNING = 1
NRPE_CRITICAL = 2
NRPE_UNKNOWN = 3

_NRPE_STRUCT = ">hhIh"
_BUFLEN = 1024 + 2 # fuck alignment

PACKET_SIZE = _BUFLEN + 10


def _create_packet(version,_type, crc, result, buffer):
    assert isinstance(buffer,str)
    assert len(buffer)<= _BUFLEN
    return struct.pack(_NRPE_STRUCT, version, _type, crc, result) + buffer.ljust(_BUFLEN,'\0')

def _parse_packet(packet):
    assert isinstance(packet,str) and len(packet)==(PACKET_SIZE)
    version, _type, crc, result = struct.unpack(_NRPE_STRUCT, packet[:10])
    buffer = packet[10:]
    return version, _type, crc, result, buffer

def create_request(version, buffer):
    """ Creates a request packet and returns it as a byte string.
    buffer is a command to be sent, version should be 2 for current versions of NRPE. """
    p1 = _create_packet(version, NRPE_REQUEST, 0, NRPE_OK, buffer)
    crc = binascii.crc32(p1) & 0xffffffff
    return _create_packet(version, NRPE_REQUEST, crc, NRPE_OK, buffer)

def parse_response(response):
    """ Parses response packet into (version, _type, crc, result, buffer).
    version will probably be 2, _type will always be NRPE_RESPONSE,
    result is one of NRPE_OK, NRPE_WARNING, NRPE_CRITICAL and NRPE_UNKNOWN,
    buffer is response string (and random crap)"""
    version, _type, crc, result, buffer = _parse_packet(response)
    p2 = _create_packet(version, _type, 0, result, buffer)
    calculated_crc = binascii.crc32(p2) & 0xffffffff
    assert crc == calculated_crc
    return version, _type, crc, result, buffer

def check_nrpe(host, command, port=5666, timeout=10, use_ssl=False):
    """ You should use this function if you just need to make a request
    and don't want to bother with how the protocol works. You give it a
    command and a hostname, it gives you state code and status string.
    (no crap in status string)."""
    if use_ssl:
        conn = ssl.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                               ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH")
    else:
        conn = socket.create_connection((host, port), timeout=timeout)
    req = create_request(2, command)
    conn.sendall(req)

    res = conn.recv(PACKET_SIZE)

    version, _type, crc, result, buffer = parse_response(res)
    buffer = buffer.split('\0',1)[0]
    return result, buffer

if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser('Python implementation of NRPE protocol')
    parser.add_argument('host', metavar='HOST', help='Server IP or hostname')
    parser.add_argument('command', metavar='COMMAND', help='NRPE command')
    args = parser.parse_args()

    print check_nrpe(args.host, args.command)
