import asyncio
import atexit
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import urllib.parse

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
except ImportError:
    AESGCMSIV = None

HOST = '0.0.0.0'
PORT = 8053
DOH_HOST = 'cloudflare-dns.com'
DOH_IP = '1.1.1.1'
DOH_PATH = '/dns-query'
PUBLIC_NAME = 'localhost'
LOCAL_OPENSSL = '/home/user/openssl-4.1.0-local/bin/openssl'
DEFAULT_OPENSSL = LOCAL_OPENSSL if os.path.exists(LOCAL_OPENSSL) else 'openssl'
OPENSSL_BIN = os.environ.get('OPENSSL_BIN', DEFAULT_OPENSSL)
AEAD_ENABLED = os.environ.get('PROXY_AEAD', '1') != '0'
AEAD_FRAME_MAX = 32768
AEAD_PADDING_SIZES = (4096, 8192, 12288, 16384, 24576, 32768)
AEAD_HEADER_PLAIN_SIZE = struct.calcsize('!QII')
AEAD_NONCE_SIZE = 12
AEAD_TAG_SIZE = 16
AEAD_KEY_SIZE = 32
AEAD_KEY_CONTROL = bytes([75])
AEAD_HEADER_AAD = b'proxy-aead-aes-256-gcm-siv-v1-header'
AEAD_PAYLOAD_AAD = b'proxy-aead-aes-256-gcm-siv-v1-payload'
MAX_BODY = 16777216
UDP_TIMEOUT = 8.0
MEM = {}
TMPDIR = str()
SERVER_CTX = None
CLIENT_CTX = None
ECH_CONFIG = str()
ECH_B64 = str()


def run_cmd(args, timeout=6):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr
    except Exception as error:
        return 127, str(error)


def read_file_bytes(path):
    try:
        with open(path, 'rb') as stream:
            return stream.read()
    except Exception:
        return bytes()


def remove_file(path):
    try:
        os.remove(path)
    except Exception:
        pass


def init_aead_crypto():
    if AEAD_ENABLED and AESGCMSIV is None:
        raise RuntimeError('cryptography with AESGCMSIV is required')


def generate_aead_key():
    init_aead_crypto()
    return AESGCMSIV.generate_key(bit_length=256)


def aead_seal(key, nonce, aad, plaintext):
    init_aead_crypto()
    return AESGCMSIV(key).encrypt(nonce, plaintext, aad)


def aead_open(key, nonce, aad, sealed):
    if len(sealed) < AEAD_TAG_SIZE:
        raise ValueError('AES-256-GCM-SIV frame is truncated')
    init_aead_crypto()
    try:
        return AESGCMSIV(key).decrypt(nonce, sealed, aad)
    except Exception as error:
        raise ValueError('AES-256-GCM-SIV authentication failed') from error


def parse_aead_key(value):
    text = value.strip()
    if len(text) == 64:
        try:
            key = bytes.fromhex(text)
            if len(key) == 32:
                return key
        except Exception:
            pass
    try:
        padded = text + ('=' * ((4 - len(text) % 4) % 4))
        key = base64.b64decode(padded, validate=True)
        if len(key) == 32:
            return key
    except Exception:
        pass
    raise ValueError('PROXY_AEAD_KEY must contain 32 bytes')


def aead_key_from_writer(writer):
    configured = os.environ.get('PROXY_AEAD_KEY', str())
    if configured:
        return parse_aead_key(configured)
    ssl_object = writer.get_extra_info('ssl_object')
    if ssl_object is None:
        raise RuntimeError('AES-256-GCM-SIV requires TLS')
    binding = ssl_object.get_channel_binding()
    if not binding:
        raise RuntimeError('TLS channel binding is unavailable')
    return hmac.new(b'proxy-aead-key-v1', binding, hashlib.sha256).digest()


def make_aead_frame(key, sequence, payload):
    if len(payload) > AEAD_FRAME_MAX:
        raise ValueError('AES-256-GCM-SIV frame is too large')
    wire_length = secrets.choice(tuple(size for size in AEAD_PADDING_SIZES if size >= len(payload)))
    wire_payload = payload + bytes(wire_length - len(payload))
    header_nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    header_plaintext = struct.pack('!QII', sequence, len(payload), wire_length)
    header_sealed = aead_seal(key, header_nonce, AEAD_HEADER_AAD, header_plaintext)
    payload_nonce = secrets.token_bytes(AEAD_NONCE_SIZE)
    payload_aad = AEAD_PAYLOAD_AAD + header_nonce + header_sealed + payload_nonce
    payload_sealed = aead_seal(key, payload_nonce, payload_aad, wire_payload)
    return header_nonce + header_sealed + payload_nonce + payload_sealed


class AeadReader:
    def __init__(self, reader, key):
        self.reader = reader
        self.key = key
        self.buffer = bytearray()
        self.sequence = 0
        self.eof = False

    async def receive_frame(self):
        if self.eof:
            return False
        try:
            header_nonce = await self.reader.readexactly(AEAD_NONCE_SIZE)
        except asyncio.IncompleteReadError as error:
            if not error.partial:
                self.eof = True
                return False
            raise
        header_sealed = await self.reader.readexactly(AEAD_HEADER_PLAIN_SIZE + AEAD_TAG_SIZE)
        header_plaintext = aead_open(self.key, header_nonce, AEAD_HEADER_AAD, header_sealed)
        sequence, length, wire_length = struct.unpack('!QII', header_plaintext)
        if sequence != self.sequence:
            raise ValueError('AES-256-GCM-SIV sequence mismatch')
        if length > AEAD_FRAME_MAX or wire_length not in AEAD_PADDING_SIZES or length > wire_length:
            raise ValueError('AES-256-GCM-SIV frame length is invalid')
        payload_nonce = await self.reader.readexactly(AEAD_NONCE_SIZE)
        payload_sealed = await self.reader.readexactly(wire_length + AEAD_TAG_SIZE)
        payload_aad = AEAD_PAYLOAD_AAD + header_nonce + header_sealed + payload_nonce
        wire_payload = aead_open(self.key, payload_nonce, payload_aad, payload_sealed)
        self.sequence += 1
        self.buffer.extend(wire_payload[:length])
        return True

    async def read(self, size=-1):
        if size == 0:
            return bytes()
        if size < 0:
            chunks = [bytes(self.buffer)]
            self.buffer.clear()
            while await self.receive_frame():
                chunks.append(bytes(self.buffer))
                self.buffer.clear()
            return str().encode().join(chunks)
        if not self.buffer and not self.eof:
            await self.receive_frame()
        output = bytes(self.buffer[:size])
        del self.buffer[:size]
        return output

    async def readexactly(self, size):
        while len(self.buffer) < size:
            if not await self.receive_frame():
                raise asyncio.IncompleteReadError(bytes(self.buffer), size)
        output = bytes(self.buffer[:size])
        del self.buffer[:size]
        return output

    async def readline(self):
        while True:
            position = self.buffer.find(b'\n')
            if position >= 0:
                end = position + 1
                output = bytes(self.buffer[:end])
                del self.buffer[:end]
                return output
            if self.eof:
                output = bytes(self.buffer)
                self.buffer.clear()
                return output
            if not await self.receive_frame() and not self.buffer:
                return bytes()

    async def readuntil(self, separator=b'\n'):
        if not separator:
            raise ValueError('separator is empty')
        while True:
            position = self.buffer.find(separator)
            if position >= 0:
                end = position + len(separator)
                output = bytes(self.buffer[:end])
                del self.buffer[:end]
                return output
            if self.eof:
                raise asyncio.IncompleteReadError(bytes(self.buffer), None)
            await self.receive_frame()


class AeadWriter:
    def __init__(self, writer, key):
        self.writer = writer
        self.key = key
        self.buffer = bytearray()
        self.sequence = 0

    def write(self, data):
        if data:
            self.buffer.extend(data)

    async def drain(self):
        while self.buffer:
            payload = bytes(self.buffer[:AEAD_FRAME_MAX])
            del self.buffer[:AEAD_FRAME_MAX]
            self.writer.write(make_aead_frame(self.key, self.sequence, payload))
            self.sequence += 1
            await self.writer.drain()
        await self.writer.drain()

    def write_eof(self):
        self.writer.write_eof()

    def close(self):
        self.writer.close()

    def is_closing(self):
        return self.writer.is_closing()

    async def wait_closed(self):
        await self.writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return self.writer.get_extra_info(name, default)


async def accept_aead_stream(reader, writer):
    bootstrap_key = aead_key_from_writer(writer)
    session_key = generate_aead_key()
    bootstrap_writer = AeadWriter(writer, bootstrap_key)
    bootstrap_writer.write(AEAD_KEY_CONTROL + session_key)
    await bootstrap_writer.drain()
    return AeadReader(reader, session_key), AeadWriter(writer, session_key)


async def open_aead_stream(reader, writer):
    bootstrap_key = aead_key_from_writer(writer)
    bootstrap_reader = AeadReader(reader, bootstrap_key)
    control = await bootstrap_reader.readexactly(1 + AEAD_KEY_SIZE)
    if control[:1] != AEAD_KEY_CONTROL:
        raise ValueError('AES-256-GCM-SIV key exchange failed')
    session_key = control[1:]
    return AeadReader(reader, session_key), AeadWriter(writer, session_key)


def wrap_aead_stream(reader, writer, key=None):
    selected_key = key if key is not None else aead_key_from_writer(writer)
    return AeadReader(reader, selected_key), AeadWriter(writer, selected_key)


def valid_base64(value):
    if len(value) < 20:
        return False
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    for char in value:
        if char not in alphabet:
            return False
    try:
        base64.b64decode(value + ('=' * ((4 - len(value) % 4) % 4)), validate=True)
        return True
    except Exception:
        return False


def extract_ech_config(data):
    if not data:
        return str()
    try:
        text = data.decode(errors='ignore') if isinstance(data, bytes) else str(data)
    except Exception:
        return str()
    quoted = chr(34)
    for begin_marker, end_marker in (('-----BEGIN ECHCONFIG-----', '-----END ECHCONFIG-----'), ('-----BEGIN ECH CONFIG-----', '-----END ECH CONFIG-----')):
        begin = text.find(begin_marker)
        end = text.find(end_marker, begin + len(begin_marker)) if begin >= 0 else -1
        if begin >= 0 and end > begin:
            section = text[begin + len(begin_marker):end].splitlines()
            joined = str().join(item.strip() for item in section)
            if valid_base64(joined):
                return joined
    for line in text.splitlines():
        value = line.strip()
        lower = value.lower()
        marker = lower.find('ech=')
        if marker >= 0:
            item = value[marker + 4:].strip()
            if item.startswith(quoted):
                item = item[1:].split(quoted, 1)[0]
            else:
                item = item.split()[0].rstrip('.')
            if valid_base64(item):
                return item
        marker = value.find('AEX')
        if marker >= 0:
            item = value[marker:].split()[0].strip(quoted).strip()
            if valid_base64(item):
                return item
    begin = text.find('BEGIN ECH CONFIG')
    end = text.find('END ECH CONFIG')
    if begin >= 0 and end > begin:
        section = text[begin:].splitlines()[1:]
        joined = str().join(item.strip() for item in section if 'END ECH CONFIG' not in item)
        if valid_base64(joined):
            return joined
    return str()


def gen_tls(tmpdir):
    key_path = os.path.join(tmpdir, 'key.pem')
    cert_path = os.path.join(tmpdir, 'cert.pem')
    subject_alt_name = 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0'
    command = [OPENSSL_BIN, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key_path, '-out', cert_path, '-days', '365', '-subj', '/CN=localhost', '-addext', subject_alt_name]
    code, output = run_cmd(command, 20)
    if not os.path.exists(key_path) or not os.path.exists(cert_path):
        command = [OPENSSL_BIN, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key_path, '-out', cert_path, '-days', '365', '-subj', '/CN=localhost']
        code, fallback_output = run_cmd(command, 20)
        output = output + fallback_output
    MEM['tls_code'] = code
    MEM['tls_output'] = output[-4000:]
    MEM['key_bytes'] = read_file_bytes(key_path)
    MEM['cert_bytes'] = read_file_bytes(cert_path)
    if not MEM['key_bytes'] or not MEM['cert_bytes']:
        raise RuntimeError('OpenSSL certificate generation failed')
    return key_path, cert_path


def gen_ech(tmpdir, public_name):
    ech_path = os.path.join(tmpdir, 'ech.pem')
    outputs = []
    commands = [
        [OPENSSL_BIN, 'ech', '-public_name', public_name, '-out', ech_path],
        [OPENSSL_BIN, 'ech', '-public_name', public_name, '-pemout', ech_path],
        [OPENSSL_BIN, 'ech', '-public_name', public_name, '-out', ech_path, '-verbose']
    ]
    for command in commands:
        if os.path.exists(ech_path):
            break
        code, output = run_cmd(command, 8)
        outputs.append(str(code) + ' ' + output[-2000:])
    data = read_file_bytes(ech_path)
    value = extract_ech_config(data)
    if not value:
        value = extract_ech_config('\n'.join(outputs))
    MEM['ech_output'] = '\n'.join(outputs)[-6000:]
    MEM['ech_bytes'] = data
    MEM['ech_b64'] = value
    return ech_path, value


def probe_openssl():
    version_code, version = run_cmd([OPENSSL_BIN, 'version'], 4)
    help_code, help_text = run_cmd([OPENSSL_BIN, 's_client', '-help'], 4)
    MEM['openssl_version'] = version[-1000:]
    MEM['openssl_version_code'] = version_code
    MEM['sclient_help_code'] = help_code
    MEM['sclient_help'] = help_text[-20000:]
    MEM['sclient_grease'] = '-grease' in help_text
    MEM['sclient_ech_grease'] = '-ech_grease' in help_text
    if '-ech_config_list' in help_text:
        MEM['ech_config_option'] = '-ech_config_list'
    elif '-ech_config ' in help_text:
        MEM['ech_config_option'] = '-ech_config'
    else:
        MEM['ech_config_option'] = str()
    MEM['sclient_ech_config'] = bool(MEM['ech_config_option'])
    return help_text


def gen_grease():
    help_text = str(MEM.get('sclient_help', str()))
    command = [OPENSSL_BIN, 's_client', '-connect', DOH_IP + ':443', '-servername', DOH_HOST, '-grease', '-ech_grease', '-ech_grease_type', '0xfe0d', '-alpn', 'h2']
    code, output = run_cmd(command, 5)
    command_two = [OPENSSL_BIN, 's_client', '-connect', DOH_IP + ':443', '-servername', DOH_HOST, '-grease', '-ech_grease', '-alpn', 'h2']
    code_two, output_two = run_cmd(command_two, 5)
    if '-grease' not in help_text:
        code_three, output_three = run_cmd([OPENSSL_BIN, 's_client', '-connect', DOH_IP + ':443', '-servername', DOH_HOST, '-alpn', 'h2'], 5)
    else:
        code_three, output_three = code_two, str()
    MEM['grease_code'] = code
    MEM['grease_code_two'] = code_two
    MEM['grease_code_three'] = code_three
    MEM['grease_output'] = (output + output_two + output_three)[-10000:]
    return [output[-2500:], output_two[-2500:], output_three[-2500:]]


def build_server_context(key_path, cert_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    context.set_alpn_protocols(['http/1.1'])
    try:
        context.set_ecdh_curves('X25519:P-256')
    except Exception:
        pass
    return context


def build_client_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['h2', 'http/1.1'])
    try:
        context.set_ecdh_curves('X25519:P-256')
    except Exception:
        pass
    return context


def parse_http_body(data):
    separator = data.find(b'\r\n\r\n')
    if separator < 0:
        return bytes()
    head = data[:separator].decode(errors='ignore').lower()
    body = data[separator + 4:]
    if 'transfer-encoding: chunked' not in head:
        length = None
        for line in head.split('\r\n'):
            if line.startswith('content-length:'):
                try:
                    length = int(line.split(':', 1)[1].strip())
                except Exception:
                    length = None
                break
        return body[:length] if length is not None else body
    result = bytearray()
    position = 0
    while position < len(body):
        line_end = body.find(b'\r\n', position)
        if line_end < 0:
            break
        try:
            size = int(body[position:line_end].split(b';', 1)[0], 16)
        except Exception:
            break
        position = line_end + 2
        if size == 0:
            break
        result.extend(body[position:position + size])
        position += size + 2
    return bytes(result)


async def close_writer(writer):
    try:
        writer.close()
    except Exception:
        return
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def doh_query(name, qtype):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['http/1.1'])
    writer = None
    try:
        reader, writer = await asyncio.open_connection(DOH_IP, 443, ssl=context, server_hostname=DOH_HOST)
        encoded_name = urllib.parse.quote(name, safe=str())
        path = DOH_PATH + '?name=' + encoded_name + '&type=' + qtype
        ech_header = str()
        if ECH_B64:
            ech_header = 'Ech-Config: ' + ECH_B64 + '\r\n'
        request = 'GET ' + path + ' HTTP/1.1\r\nHost: ' + DOH_HOST + '\r\nAccept: application/dns-json\r\n' + ech_header + 'Connection: close\r\n\r\n'
        writer.write(request.encode())
        await writer.drain()
        data = await reader.read(262144)
        body = parse_http_body(data)
        if not body:
            return {}
        return json.loads(body.decode(errors='strict'))
    except Exception:
        return {}
    finally:
        if writer is not None:
            await close_writer(writer)


async def doh_get_ech(hostname):
    result = await doh_query(hostname, 'HTTPS')
    quoted = chr(34)
    value = str()
    try:
        for answer in result.get('Answer', []):
            data = str(answer.get('data', str()))
            marker = data.lower().find('ech=')
            if marker < 0:
                continue
            item = data[marker + 4:].strip()
            if item.startswith(quoted):
                item = item[1:].split(quoted, 1)[0]
            else:
                item = item.split()[0].rstrip('.')
            if valid_base64(item):
                value = item
                break
    except Exception:
        value = str()
    if value:
        MEM.setdefault('doh_ech', {})[hostname] = value
    return value


async def resolve_via_doh(hostname):
    if not hostname:
        return str()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, hostname)
            return hostname
        except Exception:
            pass
    for qtype in ('A', 'AAAA'):
        result = await doh_query(hostname, qtype)
        try:
            for answer in result.get('Answer', []):
                candidate = str(answer.get('data', str()))
                if qtype == 'A':
                    socket.inet_pton(socket.AF_INET, candidate)
                else:
                    socket.inet_pton(socket.AF_INET6, candidate)
                return candidate
        except Exception:
            pass
    try:
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        if records:
            return records[0][4][0]
    except Exception:
        pass
    return hostname


def address_family(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return socket.AF_INET6
    except Exception:
        return socket.AF_INET


def make_tfo_socket(family=socket.AF_INET):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_FASTOPEN_CONNECT', 30), 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_FASTOPEN', 23), 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass
    return sock


async def open_tfo_stream(address, port, context=None, server_hostname=None):
    family = address_family(address)
    sock = make_tfo_socket(family)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        if family == socket.AF_INET6:
            await loop.sock_connect(sock, (address, port, 0, 0))
        else:
            await loop.sock_connect(sock, (address, port))
        return await asyncio.open_connection(sock=sock, ssl=context, server_hostname=server_hostname)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


async def open_stream(host, port, context=None, server_hostname=None):
    address = await resolve_via_doh(host)
    try:
        return await open_tfo_stream(address, port, context, server_hostname)
    except Exception:
        return await asyncio.open_connection(host, port, ssl=context, server_hostname=server_hostname)


def make_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
    except Exception:
        pass
    sock.bind((HOST, PORT))
    sock.listen(128)
    sock.setblocking(False)
    return sock


def udp_encode(host, port, payload):
    host_bytes = host.encode()
    if len(host_bytes) > 255:
        raise ValueError('UDP host is too long')
    if len(payload) + len(host_bytes) + 3 > 65535:
        raise ValueError('UDP packet is too large')
    body = struct.pack('!BH', len(host_bytes), port) + host_bytes + payload
    return struct.pack('!H', len(body)) + body


def udp_decode_one(buffer):
    if len(buffer) < 2:
        return None
    length = struct.unpack('!H', buffer[:2])[0]
    if length < 3 or len(buffer) < length + 2:
        return None
    body = buffer[2:length + 2]
    host_length = body[0]
    if len(body) < host_length + 3:
        return None
    try:
        host = body[3:3 + host_length].decode()
    except Exception:
        return None
    port = struct.unpack('!H', body[1:3])[0]
    payload = body[3 + host_length:]
    return host, port, payload, length + 2


class UdpReceiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.queue = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        try:
            self.queue.put_nowait(data)
        except Exception:
            pass

    def error_received(self, error):
        try:
            self.queue.put_nowait(bytes())
        except Exception:
            pass

    def connection_lost(self, error):
        try:
            self.queue.put_nowait(bytes())
        except Exception:
            pass


async def udp_exchange(host, port, payload):
    address = await resolve_via_doh(host)
    family = address_family(address)
    loop = asyncio.get_running_loop()
    receiver = UdpReceiver()
    remote = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    transport = None
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: receiver, family=family, remote_addr=remote)
        transport.sendto(payload)
        return await asyncio.wait_for(receiver.queue.get(), UDP_TIMEOUT)
    except Exception:
        return bytes()
    finally:
        if transport is not None:
            transport.close()


async def handle_framed_udp(reader, writer):
    buffer = bytearray()
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            buffer.extend(data)
            while True:
                decoded = udp_decode_one(buffer)
                if decoded is None:
                    break
                host, port, payload, consumed = decoded
                del buffer[:consumed]
                response = await udp_exchange(host, port, payload)
                writer.write(udp_encode(host, port, response))
                await writer.drain()
    except Exception:
        pass
    await close_writer(writer)


class ProcessWriter:
    def __init__(self, process):
        self.process = process
        self.stream = process.stdin

    def write(self, data):
        if self.stream is not None and not self.stream.is_closing():
            self.stream.write(data)

    async def drain(self):
        if self.stream is not None and not self.stream.is_closing():
            await self.stream.drain()

    def write_eof(self):
        if self.stream is not None and not self.stream.is_closing():
            self.stream.write_eof()

    def is_closing(self):
        return self.stream is None or self.stream.is_closing()

    def close(self):
        if self.stream is not None and not self.stream.is_closing():
            self.stream.close()

    async def wait_closed(self):
        try:
            await asyncio.wait_for(self.process.wait(), 3)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass


class CombinedTransport:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.alpn = 'h2'
        self.h2 = True
        self.grpc = True
        self.modes = ('h2', 'grpc')

    async def send_grpc(self, payload):
        header = struct.pack('!BI', 0, len(payload))
        self.writer.write(header + payload)
        await self.writer.drain()

    async def recv_grpc(self):
        header = await self.reader.readexactly(5)
        flag, length = struct.unpack('!BI', header)
        if flag not in (0, 1):
            raise ValueError('invalid gRPC compression flag')
        return await self.reader.readexactly(length)

    async def send_h2(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def recv_h2(self):
        return await self.reader.read(65536)

    async def send_http1(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def send_combined(self, data, mode=False):
        if mode is True or mode == 'grpc':
            await self.send_grpc(data)
        else:
            await self.send_h2(data)

    async def recv_combined(self, mode=False):
        if mode is True or mode == 'grpc':
            return await self.recv_grpc()
        return await self.recv_h2()


def split_host_port(value, default_port):
    item = value.strip()
    if '://' in item:
        parsed = urllib.parse.urlsplit(item)
        host = parsed.hostname or str()
        return host, parsed.port or default_port
    if item.startswith('['):
        closing = item.find(']')
        if closing > 0:
            host = item[1:closing]
            tail = item[closing + 1:]
            if tail.startswith(':'):
                try:
                    return host, int(tail[1:])
                except Exception:
                    pass
            return host, default_port
    if item.count(':') == 1:
        host, port_value = item.rsplit(':', 1)
        try:
            return host, int(port_value)
        except Exception:
            pass
    return item, default_port


def pac_body():
    lines = [
        'function FindProxyForURL(url, host) {',
        'if (isPlainHostName(host)) return ' + chr(39) + 'DIRECT' + chr(39) + ';',
        'if (host == ' + chr(39) + '127.0.0.1' + chr(39) + ') return ' + chr(39) + 'DIRECT' + chr(39) + ';',
        'if (host == ' + chr(39) + 'localhost' + chr(39) + ') return ' + chr(39) + 'DIRECT' + chr(39) + ';',
        'return ' + chr(39) + 'PROXY 0.0.0.0:8053' + chr(39) + ';',
        '}'
    ]
    return '\n'.join(lines)


def is_pac_target(target):
    value = target
    if value.startswith('http://') or value.startswith('https://'):
        try:
            value = urllib.parse.urlsplit(value).path
        except Exception:
            return False
    return value in ('/wpad.dat', '/proxy.pac')


async def send_pac(writer):
    body = pac_body().encode()
    response = 'HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: ' + str(len(body)) + '\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'
    writer.write(response.encode() + body)
    await writer.drain()
    await close_writer(writer)


async def send_error(writer, status, text):
    body = text.encode()
    response = 'HTTP/1.1 ' + status + '\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ' + str(len(body)) + '\r\nConnection: close\r\n\r\n'
    try:
        writer.write(response.encode() + body)
        await writer.drain()
    except Exception:
        pass
    await close_writer(writer)


async def read_request_body(reader, headers):
    value = headers.get('content-length')
    if value is not None:
        try:
            length = int(value)
        except Exception:
            length = 0
        if length < 0 or length > MAX_BODY:
            raise ValueError('request body is too large')
        if length:
            return await reader.readexactly(length)
        return bytes()
    if 'chunked' in headers.get('transfer-encoding', str()).lower():
        data = bytearray()
        while True:
            line = await reader.readline()
            if not line:
                break
            data.extend(line)
            try:
                size = int(line.split(b';', 1)[0].strip(), 16)
            except Exception:
                raise ValueError('invalid chunked request')
            if size == 0:
                while True:
                    trailer = await reader.readline()
                    data.extend(trailer)
                    if trailer in (b'\r\n', b'\n', bytes()):
                        break
                break
            chunk = await reader.readexactly(size + 2)
            data.extend(chunk)
            if len(data) > MAX_BODY:
                raise ValueError('request body is too large')
        return bytes(data)
    return bytes()


def make_forward_request(method, path, host_header, headers, body):
    hop = {'proxy-connection', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'upgrade'}
    lines = [method + ' ' + path + ' HTTP/1.1', 'Host: ' + host_header]
    for key, value in headers.items():
        if key in hop or key == 'host':
            continue
        lines.append(key + ': ' + value)
    if body and 'content-length' not in headers and 'transfer-encoding' not in headers:
        lines.append('Content-Length: ' + str(len(body)))
    lines.append('Connection: close')
    lines.append(str())
    lines.append(str())
    return '\r\n'.join(lines).encode() + body


def openssl_bridge_available(use_ech):
    if os.environ.get('PROXY_OPENSSL_BRIDGE', '1') == '0':
        return False
    if not MEM.get('sclient_grease'):
        return False
    if use_ech and not MEM.get('sclient_ech_config'):
        return False
    return True


async def open_openssl_bridge(host, port, sni, ech_config, grpc_mode=False):
    flags = str(MEM.get('sclient_help', str()))
    alpn = 'h2' if grpc_mode else 'http/1.1'
    connect_target = host + ':' + str(port)
    if ':' in host and not host.startswith('['):
        connect_target = '[' + host + ']:' + str(port)
    command = [OPENSSL_BIN, 's_client', '-connect', connect_target, '-servername', sni, '-quiet', '-ign_eof', '-alpn', alpn]
    ech_option = str(MEM.get('ech_config_option', str()))
    if ech_config and ech_option:
        command.extend([ech_option, ech_config, '-tls1_3'])
    else:
        if '-grease' in flags:
            command.append('-grease')
        if '-ech_grease' in flags:
            command.append('-ech_grease')
        if '-ech_grease_type' in flags:
            command.extend(['-ech_grease_type', '0xfe0d'])
    process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    await asyncio.sleep(0.04)
    if process.returncode is not None:
        await process.wait()
        raise ConnectionError('OpenSSL upstream connection failed')
    return process.stdout, ProcessWriter(process)


async def open_upstream(host, port, tls, grpc_mode=False):
    address = await resolve_via_doh(host)
    host_ech = str()
    if tls:
        try:
            host_ech = await doh_get_ech(host)
        except Exception:
            host_ech = str()
    use_bridge = tls and openssl_bridge_available(bool(host_ech)) and not grpc_mode
    if use_bridge:
        try:
            return await open_openssl_bridge(address, port, host, host_ech, grpc_mode)
        except Exception:
            pass
    if tls:
        context = CLIENT_CTX if CLIENT_CTX is not None else build_client_context()
        try:
            return await open_tfo_stream(address, port, context, host)
        except Exception:
            return await asyncio.open_connection(host, port, ssl=context, server_hostname=host)
    try:
        return await open_tfo_stream(address, port)
    except Exception:
        return await asyncio.open_connection(host, port)


async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    try:
        if not writer.is_closing():
            writer.write_eof()
    except Exception:
        pass


async def handle_connect(target, reader, writer):
    host, port = split_host_port(target, 443)
    if not host:
        await send_error(writer, '400 Bad Request', 'invalid CONNECT target')
        return
    upstream_reader = None
    upstream_writer = None
    try:
        upstream_reader, upstream_writer = await open_upstream(host, port, False)
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()
        await asyncio.gather(relay(reader, upstream_writer), relay(upstream_reader, writer))
    except Exception:
        await send_error(writer, '502 Bad Gateway', 'upstream connection failed')
    finally:
        if upstream_writer is not None:
            await close_writer(upstream_writer)
        await close_writer(writer)


async def handle_http(method, target, headers, reader, writer):
    body = await read_request_body(reader, headers)
    if target.startswith('http://') or target.startswith('https://'):
        parsed = urllib.parse.urlsplit(target)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or str()
        port = parsed.port or (443 if scheme == 'https' else 80)
        path = parsed.path or '/'
        if parsed.query:
            path = path + '?' + parsed.query
    else:
        scheme = 'http'
        host, port = split_host_port(headers.get('host', str()), 80)
        path = target or '/'
    if not host:
        await send_error(writer, '400 Bad Request', 'host is missing')
        return
    host_header = host
    if (scheme == 'http' and port != 80) or (scheme == 'https' and port != 443):
        host_header = host + ':' + str(port)
    content_type = headers.get('content-type', str()).lower()
    grpc_mode = 'grpc' in content_type
    upstream_reader = None
    upstream_writer = None
    try:
        upstream_reader, upstream_writer = await open_upstream(host, port, scheme == 'https', grpc_mode)
        transport = CombinedTransport(upstream_reader, upstream_writer)
        request = make_forward_request(method, path, host_header, headers, body)
        await transport.send_http1(request)
        await relay(upstream_reader, writer)
    except Exception:
        await send_error(writer, '502 Bad Gateway', 'upstream request failed')
    finally:
        if upstream_writer is not None:
            await close_writer(upstream_writer)
        await close_writer(writer)


async def handle_client(reader, writer):
    try:
        if AEAD_ENABLED:
            reader, writer = await accept_aead_stream(reader, writer)
            first = await asyncio.wait_for(reader.readline(), 15)
        else:
            first = await reader.readline()
        if not first:
            await close_writer(writer)
            return
        line = first.decode(errors='ignore').strip()
        parts = line.split()
        if len(parts) < 3:
            await send_error(writer, '400 Bad Request', 'invalid request line')
            return
        method = parts[0].upper()
        target = parts[1]
        headers = {}
        while True:
            header_line = await reader.readline()
            if not header_line or header_line in (b'\r\n', b'\n'):
                break
            text = header_line.decode(errors='ignore').strip()
            if ':' in text:
                key, value = text.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        if is_pac_target(target):
            await send_pac(writer)
            return
        if method == 'UDP' and headers.get('x-udp-over-tcp') != '1' and headers.get('udp-over-tcp') != '1':
            host, port = split_host_port(target, 53)
            payload = await read_request_body(reader, headers)
            response = await udp_exchange(host, port, payload)
            writer.write(udp_encode(host, port, response))
            await writer.drain()
            await close_writer(writer)
            return
        if method == 'UDP' or headers.get('x-udp-over-tcp') == '1' or headers.get('udp-over-tcp') == '1':
            await handle_framed_udp(reader, writer)
            return
        if method == 'CONNECT':
            await handle_connect(target, reader, writer)
            return
        if method in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
            await handle_http(method, target, headers, reader, writer)
            return
        await send_error(writer, '405 Method Not Allowed', 'method is not supported')
    except Exception:
        await close_writer(writer)


async def amain():
    global TMPDIR, SERVER_CTX, CLIENT_CTX, ECH_CONFIG, ECH_B64
    TMPDIR = tempfile.mkdtemp(prefix='proxy_')
    MEM['tmpdir'] = TMPDIR
    try:
        if AEAD_ENABLED:
            init_aead_crypto()
        key_path, cert_path = await asyncio.to_thread(gen_tls, TMPDIR)
        ech_path, generated_ech = await asyncio.to_thread(gen_ech, TMPDIR, PUBLIC_NAME)
        ECH_B64 = generated_ech
        ECH_CONFIG = generated_ech
        await asyncio.to_thread(probe_openssl)
        await asyncio.to_thread(gen_grease)
        try:
            public_ech = await doh_get_ech(PUBLIC_NAME)
            if public_ech:
                ECH_B64 = public_ech
                ECH_CONFIG = public_ech
        except Exception:
            pass
        SERVER_CTX = build_server_context(key_path, cert_path)
        CLIENT_CTX = build_client_context()
        remove_file(key_path)
        remove_file(cert_path)
        remove_file(ech_path)
        listener = make_listener()
        server = await asyncio.start_server(handle_client, sock=listener, ssl=SERVER_CTX, limit=65536)
        print('listening on ' + HOST + ':' + str(PORT), flush=True)
        print('openssl ' + str(MEM.get('openssl_version', str())).splitlines()[0], flush=True)
        print('https proxy with openssl tls', flush=True)
        print('echconfig ' + str(ECH_B64[:80]), flush=True)
        print('doh ' + DOH_HOST, flush=True)
        print('tfo 1', flush=True)
        print('pac /wpad.dat /proxy.pac', flush=True)
        print('transport h2 grpc', flush=True)
        print('aead aes-256-gcm-siv cryptography ' + ('on' if AEAD_ENABLED else 'off'), flush=True)
        print('tls-in-tls guard padded frames', flush=True)
        try:
            async with server:
                await server.serve_forever()
        finally:
            server.close()
            await server.wait_closed()
    finally:
        cleanup()


def cleanup():
    global TMPDIR, SERVER_CTX, CLIENT_CTX, ECH_CONFIG, ECH_B64
    try:
        if TMPDIR and os.path.exists(TMPDIR):
            shutil.rmtree(TMPDIR, ignore_errors=True)
    except Exception:
        pass
    try:
        MEM.clear()
    except Exception:
        pass
    TMPDIR = str()
    SERVER_CTX = None
    CLIENT_CTX = None
    ECH_CONFIG = str()
    ECH_B64 = str()


def main():
    atexit.register(cleanup)
    try:
        try:
            import uvloop
            uvloop.run(amain())
        except ImportError:
            asyncio.run(amain())
    finally:
        cleanup()


if __name__ == '__main__':
    main()
