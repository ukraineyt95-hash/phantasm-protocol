# Phantasm Protocol

[English](#english) · [Русский](#русский)

## English

Phantasm is a Python, TLS-wrapped HTTP/CONNECT proxy with optional UDP-over-TCP forwarding and an authenticated, padded application framing layer. The current implementation is a single server script (`phantasm.py`); a compatible client must implement its TLS connection and framing.

### How it works

- Listens on TCP `8053` and accepts proxy requests inside TLS. It supports HTTP proxy requests, `CONNECT` tunnels, PAC files (`/wpad.dat`, `/proxy.pac`), and a simple UDP relay mode.
- With AEAD enabled (the default), proxy-stream data is carried in AES-256-GCM-SIV authenticated frames. The frame plaintext is padded into size buckets from 4 to 32 KiB; sequence numbers and authenticated headers detect tampering, truncation, or reordering. A per-connection session key is bootstrapped over the TLS connection.
- For outbound TLS connections, it can try DNS-over-HTTPS (Cloudflare) for resolution and ECH configuration discovery. When the installed OpenSSL `s_client` supports the needed options, the script can use an OpenSSL bridge with ECH, or GREASE where real ECH is unavailable. It falls back to Python TLS when the bridge cannot be used.

### DPI and TLS-in-TLS

The design **attempts to make classification harder; it is not a guaranteed DPI bypass**. The outer TLS layer conceals proxy request contents from passive inspection. ECH, when supported by both the OpenSSL build and the destination and successfully negotiated, encrypts the inner ClientHello fields such as the real SNI. DoH avoids ordinary plaintext DNS lookups for the queries this script makes. These features do not hide the proxy server's IP address, traffic timing or total volume; GREASE is not ECH, and ECH is not available for every destination. A strict or active DPI system can still block or fingerprint the connection.

### TLS-in-TLS framing

When HTTPS is carried through `CONNECT`, the inner TLS stream is still tunneled through the outer proxy TLS session. The framing addresses the *DPI-visible TLS-in-TLS signature*: the inner ClientHello is not sent as a raw, recognizable TLS record in the outer application stream. Instead, each application chunk is wrapped in an AES-256-GCM-SIV frame:

- Chunks are split at a maximum of 32 KiB. The padded payload size is randomly selected from 4, 8, 12, 16, 24, or 32 KiB, choosing only sizes large enough for that chunk.
- The exact plaintext length, frame wire length, and sequence number are in an encrypted, authenticated header. The header is also bound to the encrypted payload as associated data.
- Padding bytes are added before encryption, so they appear as ciphertext, not as readable filler.
- An AEAD frame starts with a public 12-byte nonce, followed by the encrypted header; it does not start with plaintext HTTP or an inner TLS ClientHello. (This describes the framing inside the already-established outer TLS connection, not the outer TLS handshake.)

This hides the inner ClientHello's original size and replaces a recognizable inner TLS handshake with authenticated, padded records. That addresses the specific TLS-in-TLS fingerprint/length leak; it does not remove the fact that TLS is nested, conceal timing or total traffic volume, or guarantee evasion of every active or statistical DPI system.

### Requirements

- Python 3.9 or newer.
- `cryptography >= 42.0.0` for `AESGCMSIV` (required while AEAD is enabled, which is the default). [The class was added in cryptography 42.0.0.](https://cryptography.io/en/42.0.0/hazmat/primitives/aead/)
- OpenSSL **4.1.0 is the target for the full ECH/GREASE bridge feature set**. The script probes the binary and has fallback paths, so this is not a hard requirement for every basic proxy path; without compatible ECH/GREASE options those protections may be unavailable. OpenSSL documents the `s_client` ECH options [here](https://docs.openssl.org/4.0/man1/openssl-s_client/).

The main practical downside is the relatively demanding crypto/toolchain baseline: `cryptography >= 42.0.0` and OpenSSL 4.1.0 for the full feature set. Note that cryptography's AES-GCM-SIV support also depends on the OpenSSL library used by that Python build; its 42.0.0 changelog records support with OpenSSL 3.2.0+. [Details](https://cryptography.io/en/42.0.0/changelog/).

### References

- [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html): ECH encrypts the ClientHello under a server public key; it requires a compatible destination/configuration.
- [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html): authenticated encryption with nonce-misuse resistance.
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html): TLS protects application data but does not by itself hide traffic lengths; its record-padding mechanism is described in §5.4.
- [cryptography 42.0.0 AEAD API](https://cryptography.io/en/42.0.0/hazmat/primitives/aead/)
- [OpenSSL `s_client` ECH options](https://docs.openssl.org/4.0/man1/openssl-s_client/)

## Русский

Phantasm — Python-прокси поверх TLS с поддержкой HTTP/CONNECT, необязательной пересылкой UDP через TCP и аутентифицированным фреймированием с дополнением. Текущая реализация — один серверный скрипт (`phantasm.py`); совместимый клиент должен самостоятельно реализовать TLS-соединение и тот же формат фреймов.

### Как работает

- Слушает TCP-порт `8053` и принимает прокси-запросы внутри TLS. Поддерживаются HTTP-прокси, туннели `CONNECT`, PAC-файлы (`/wpad.dat`, `/proxy.pac`) и простой режим ретрансляции UDP.
- При включённом AEAD (по умолчанию) данные прокси-потока передаются в аутентифицированных фреймах AES-256-GCM-SIV. Полезная нагрузка дополняется до одного из размеров от 4 до 32 КиБ; номера последовательности и аутентифицированные заголовки позволяют обнаружить подмену, усечение и перестановку фреймов. Ключ сессии передаётся внутри TLS-соединения.
- Для исходящих TLS-соединений скрипт может использовать DNS-over-HTTPS (Cloudflare) для резолвинга и поиска ECH-конфигурации. Если установленный `openssl s_client` поддерживает необходимые параметры, скрипт может использовать OpenSSL-мост с ECH, а при недоступности реального ECH — GREASE. Если мост не подходит, используется резервный путь на Python TLS.

### DPI и TLS-in-TLS

Схема **пытается усложнить классификацию трафика, но не гарантирует обход DPI**. Внешний TLS скрывает содержимое прокси-запросов от пассивного наблюдателя. ECH при поддержке со стороны сборки OpenSSL и целевого сервера и при успешном согласовании шифрует поля внутреннего ClientHello, включая настоящий SNI. DoH не даёт обычным DNS-запросам, отправляемым этим скриптом, идти в открытом виде. Но эти механизмы не скрывают IP-адрес прокси, время передачи и общий объём трафика; GREASE — не ECH, а ECH поддерживается не всеми серверами. Строгая или активная DPI-система всё ещё может блокировать соединение или распознавать его по отпечатку.

### Фреймирование TLS-in-TLS

При передаче HTTPS через `CONNECT` внутренний TLS-поток всё ещё туннелируется через внешнюю TLS-сессию прокси. Фреймирование адресует **видимый для DPI признак TLS-in-TLS**: внутренний ClientHello не передаётся во внешнем потоке приложений как открытая, распознаваемая TLS-запись. Вместо этого каждый блок данных оборачивается в кадр AES-256-GCM-SIV:

- Данные делятся на блоки максимум по 32 КиБ. Размер полезной нагрузки с дополнением случайно выбирается из 4, 8, 12, 16, 24 или 32 КиБ — только из размеров, в которые помещается текущий блок.
- Точная длина открытых данных, wire-длина фрейма и sequence number находятся в зашифрованном аутентифицированном заголовке. Заголовок также включён в аутентификацию зашифрованной полезной нагрузки.
- Байты дополнения добавляются до шифрования и снаружи видны только как шифротекст, а не как открытый заполнитель.
- AEAD-фрейм начинается с публичного 12-байтового nonce, за которым идёт зашифрованный заголовок; открытого HTTP или внутреннего TLS ClientHello там нет. (Речь о фреймировании внутри уже установленного внешнего TLS-соединения, а не о рукопожатии внешнего TLS.)

Так скрывается исходный размер внутреннего ClientHello, а распознаваемое внутреннее TLS-рукопожатие заменяется аутентифицированными записями с дополнением. Это устраняет конкретную утечку размера и отпечаток TLS-in-TLS, но не сам факт вложенного TLS; тайминги и общий объём трафика остаются видимыми, поэтому это не гарантия обхода любой активной или статистической DPI-системы.

### Требования

- Python 3.9 или новее.
- `cryptography >= 42.0.0` для `AESGCMSIV` (необходима при включённом AEAD, который включён по умолчанию). [Класс появился в cryptography 42.0.0.](https://cryptography.io/en/42.0.0/hazmat/primitives/aead/)
- **OpenSSL 4.1.0 — целевая версия для полного набора возможностей ECH/GREASE-моста.** Скрипт проверяет доступные параметры и имеет резервные пути, поэтому эта версия не обязательна для каждого базового сценария прокси; без подходящих параметров ECH/GREASE соответствующие защиты могут быть недоступны. Параметры ECH для `s_client` описаны в [документации OpenSSL](https://docs.openssl.org/4.0/man1/openssl-s_client/).

Главный практический минус — сравнительно высокие требования к криптографической библиотеке и инструментам: `cryptography >= 42.0.0`, а для полного набора функций — OpenSSL 4.1.0. Поддержка AES-GCM-SIV в cryptography также зависит от версии OpenSSL, с которой собран Python; в истории cryptography 42.0.0 указана поддержка при OpenSSL 3.2.0 и новее. [Подробности](https://cryptography.io/en/42.0.0/changelog/).

### Источники

- [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html): ECH шифрует ClientHello открытым ключом сервера и требует совместимой конфигурации на целевом сервере.
- [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html): аутентифицированное шифрование с устойчивостью к ошибочному повторному использованию nonce.
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html): TLS защищает данные приложений, но сам по себе не скрывает размеры трафика; дополнение TLS-записей описано в §5.4.
- [AEAD API cryptography 42.0.0](https://cryptography.io/en/42.0.0/hazmat/primitives/aead/)
- [Параметры ECH для OpenSSL `s_client`](https://docs.openssl.org/4.0/man1/openssl-s_client/)
