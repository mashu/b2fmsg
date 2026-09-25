# b2fmsg

[![CI](https://github.com/mashu/b2fmsg/actions/workflows/ci.yml/badge.svg)](https://github.com/mashu/b2fmsg/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/mashu/b2fmsg/branch/main/graph/badge.svg)](https://codecov.io/gh/mashu/b2fmsg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Radio email over the open B2F protocol, compatible with the Winlink system. Send and receive through the Winlink CMS over the internet, through an RMS gateway on the air via Direwolf, or directly peer to peer. Runs as a CLI or in the browser ([live page](https://mashu.github.io/b2fmsg/)).

b2fmsg is an independent implementation of the [published B2F specification](https://winlink.org/B2F) and is not affiliated with the Winlink Development Team or ARSFI. You need a licence and a (free) Winlink account for your callsign to use the CMS or RMS gateways.

## Links

| Link | CLI | Browser |
| --- | --- | --- |
| Winlink CMS over the internet (telnet, `server.winlink.org:8772`) | `connect` | via bridge, `/cms` |
| RMS gateway over AX.25 packet, through Direwolf's AGW port | `connect ax25 SK0XYZ-10` | via bridge, `/agw` |
| Peer to peer over TCP (another b2fmsg, or Pat) | `connect p2p HOST:PORT CALL`, `listen` | — |

VARA and ARDOP are planned; see the roadmap.

## CLI

```bash
cargo run --release -- --call SA0KAM --locator JO89
compose                          # To, Cc, Subject, body ending with ".", attachments
msg friend@example.com Arrived at the cabin, all well
connect                          # CMS over the internet
connect ax25 SK0XYZ-10 via SK0DIG
inbox
read 1
```

Your Winlink password is asked for on the first `connect` (or read from `--password-file` / `$B2FMSG_PASSWORD`). It never leaves your computer: the gateway sends a challenge and b2fmsg answers with a hash.

For scripts and cron, `--once` runs one exchange and exits with status 1 on failure:

```bash
B2FMSG_PASSWORD=... b2fmsg --call SA0KAM --once cms
b2fmsg --call SA0KAM --once "ax25 SK0XYZ-10"
```

Messages live in `~/.local/share/b2fmsg/mailbox/<CALL>/{in,out,sent,archive}/<MID>.b2f`, the same layout Pat uses, so `--mailbox ~/.local/share/pat/mailbox` shares one mailbox between both programs.

### Direwolf

Enable the AGW port in `direwolf.conf` (it is on by default):

```
AGWPORT 8000
```

Direwolf runs the AX.25 connected-mode link (SABM, acknowledgements, retries); b2fmsg speaks B2F over it and sends frames of at most `--paclen` bytes (default 128). After the exchange it waits until Direwolf reports every frame acknowledged before disconnecting.

## Browser

Browsers cannot open the TCP connections Winlink uses, so the page talks to `b2fmsg-bridge` on your computer:

```bash
b2fmsg-bridge                     # ws://127.0.0.1:8765/cms and /agw
```

The bridge has fixed routes (`/cms` → the CMS, `/agw` → Direwolf) and accepts pages only from `https://mashu.github.io` and `localhost`, so a random website cannot drive your transmitter through it. Add origins with `--allow-origin URL`. The browser keeps its mailbox in IndexedDB; the password is used only in the page and never stored.

Prebuilt binaries for Linux, macOS, and Windows are on the [Releases](https://github.com/mashu/b2fmsg/releases) page.

## How it fits together

Everything protocol-related is network-free: callers feed received bytes and apply the returned actions, so the CLI and the WebAssembly build share one implementation.

| Module | Job |
| --- | --- |
| `lzhuf` | LZHUF compression in the FBB B2 container (CRC-16/XMODEM, length header) |
| `message` | Winlink message format, MIDs, addresses, RFC 2047 headers |
| `secure` | `;PQ` / `;PR` secure-login response |
| `session` | B2F state machine: handshake, proposals, answers, transfers, both roles |
| `telnet`, `agw` | CMS/P2P telnet login and AGWPE framing |
| `exchange` | One exchange: a link layer carrying a session, with timeouts |

## Compatibility testing

Beyond the unit tests, b2fmsg was checked against Pat's Go implementation (wl2k-go):

- LZHUF: decodes every reference stream in Pat's test data (including a real 31 kB Winlink message); Pat's decoder accepts b2fmsg's output; 600 randomised round trips in both directions, around window and lookahead boundaries. b2fmsg's encoder produces 1–3% smaller output than the reference one.
- Sessions over TCP with Pat's `fbb.Session`, in both roles (b2fmsg calling and answering), several messages each way with attachments, Latin-1 and UTF-8 subjects.
- Secure login against Pat's test vectors, and the CMS transcript from Pat's tests.
- Mailbox: b2fmsg reads messages that Pat wrote, and Pat reads b2fmsg's.

Not yet tested against a live CMS or RMS gateway; reports welcome.

## Roadmap

- VARA HF/FM and ARDOP over their TCP host interfaces (needs PTT through rigctld).
- Listening for peer-to-peer calls over AX.25.
- Auxiliary addresses and tactical calls in `;FW`.
- Resuming interrupted transfers.
