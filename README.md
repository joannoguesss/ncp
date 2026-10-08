# ncp

**ncp** (*network copy*) is a minimal downloader written in C. It does one thing: copy a file from a URL to your disk, like `cp` but over the network.

I wrote it while building **Linux From Scratch 12.4**. A fresh LFS system has OpenSSL but no `wget` or `curl`, so there is no easy way to download source packages from BLFS. `ncp` needs nothing beyond what LFS already ships.

## Features

- HTTP and HTTPS
- Follows redirects (up to 10)
- Chunked transfers
- Resume a partial download with `-c`
- Progress bar with speed, only when writing to a terminal
- Quiet mode with `-q`
- Certificate and hostname verification once `make-ca` is installed
- One C file, about 500 lines; depends only on libc and OpenSSL

## Build and install

Requirements: a C compiler, `make` and OpenSSL (all included in LFS).

```sh
make
make install
```

This installs `ncp` to `/usr/local/bin` and its manual page to `/usr/local/share/man/man1`. To install elsewhere:

```sh
make PREFIX=/usr install
```

To remove it:

```sh
make uninstall
```

## Usage

```sh
ncp [-cq] [-o file] url
```

| Option    | Meaning                                              |
|-----------|------------------------------------------------------|
| `-c`      | continue a partial download                          |
| `-o file` | save to `file` instead of the name taken from the URL |
| `-q`      | quiet, no progress (errors are still shown)          |

Examples:

```sh
ncp https://www.nano-editor.org/dist/v8/nano-8.6.tar.xz
ncp -c https://example.com/big.iso
ncp -q -o page.html https://example.com/
```

Output:

```
nano-8.6.tar.xz  64% [###################...........] 1.0 MiB 2.3 MiB/s
```

If a download is cut off, run the same command with `-c` and it continues where it stopped.

## How it works

```
  ncp https://…/nano-8.6.tar.xz
              │
              ▼
  ┌───────────────────────────┐
  │ parse the URL             │
  │ https · host · 443 · path │
  └───────────────────────────┘
              │
              ▼
  ┌───────────────────────────┐
  │ open a TCP connection     │
  │ https? ─► TLS handshake   │
  │   CA bundle?              │
  │     yes ─► verify server  │
  │     no  ─► warn, skip     │
  └───────────────────────────┘
              │
              ▼
  ┌───────────────────────────┐
  │ send   GET /path HTTP/1.1 │
  │ (+ Range: bytes=N- if -c) │
  │ read the status + headers │
  └───────────────────────────┘
              │
     3xx? ────┴──── 200 / 206
       │                │
       ▼                ▼
  follow the      ┌──────────────────────┐
  Location,       │ LOOP while data:     │
  start again     │  read 16 KB  ◄────┐  │
                  │  write to file    │  │
                  │  update the bar ──┘  │
                  └──────────────────────┘
                            │
                            ▼
                          done
```

### Code walkthrough

**`parse_url`** splits a URL like `https://host:8443/a/b?x=1` into the scheme (http or https), host, port and path. The default port is 80 for http and 443 for https.

**`conn_open`** resolves the host name with `getaddrinfo`, tries each address until one connects, and for https starts a TLS session with OpenSSL. It sets SNI (so servers hosting many sites know which one you want) and the expected host name, so the certificate must belong to that host. If the CA bundle installed by `make-ca` is missing, it warns once and skips verification.

**`conn_read`, `conn_getline`, `conn_fill`** read from the connection through a 16 KB buffer, whether it is plain TCP or TLS. The rest of the program does not care which one it is.

**`send_request`** writes the HTTP request. With `-c` it adds a `Range` header asking only for the bytes after what is already on disk.

**`read_headers`** reads the status line (`HTTP/1.1 200 OK`) and the headers ncp cares about: `Content-Length`, `Transfer-Encoding` and `Location`.

**Redirects**: on a `3xx` reply, `resolve` turns the `Location` header into a full URL (it may be absolute, start with `/`, or be relative to the current path) and ncp starts over, up to 10 times.

**`copy_body`** saves the data in one of three ways:
- **Content-Length**: read exactly that many bytes. If the connection drops early, it says so and suggests `-c`.
- **Chunked**: the body comes in pieces, each preceded by its size in hexadecimal. A size of 0 marks the end.
- **Neither**: read until the server closes the connection.

**`show`** draws the progress bar at most ten times per second. `\r` returns to the start of the line and `\033[K` clears the rest, so the bar updates in place. It is only drawn when standard error is a terminal, so logs and pipes stay clean.

**Resume**: with `-c`, ncp uses the size of the existing file as the starting point and opens it in append mode. If the server answers `200` instead of `206`, it ignored the range, so ncp starts the file from scratch. A `416` means the file is already complete.

## Security note

Until `make-ca` is installed, there is no list of trusted certificates, so ncp cannot verify HTTPS servers and prints a warning. While that is the case, always check the MD5 sum published in the BLFS book:

```sh
md5sum nano-8.6.tar.xz
```

Once `/etc/pki/tls/certs/ca-bundle.crt` exists, verification is turned on automatically, including the host name check. To use a different bundle, build with:

```sh
make CPPFLAGS='-DCA_BUNDLE="\"/path/to/bundle.crt\""'
```

## Limitations

Kept out on purpose to stay small: proxies, authentication, cookies, POST, FTP, IPv6 literal addresses in URLs (`[::1]`) and compressed transfers.

## License

MIT. See [LICENSE](LICENSE).
