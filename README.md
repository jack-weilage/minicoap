# `minicoap`

A tiny, `no_std`, zero-copy Rust library for parsing and building CoAP (Constrained Application Protocol) messages.

## Features

- `no_std` compatible
- Zero-copy message parsing
- Type-safe message builder with compile-time state checking
- Support for all common CoAP message types, request/response codes, and options
- Optional `defmt` support for embedded debugging
- Comprehensive request and response code enums with RFC documentation

## Specifications

- [RFC 7252](https://datatracker.ietf.org/doc/html/rfc7252): The Constrained Application Protocol (CoAP)
- [RFC 7959](https://datatracker.ietf.org/doc/html/rfc7959): Block-Wise Transfers in the Constrained Application Protocol (CoAP)
- [RFC 7967](https://datatracker.ietf.org/doc/html/rfc7967): Constrained Application Protocol (CoAP) Option for No Server Response
- [RFC 8132](https://datatracker.ietf.org/doc/html/rfc8132): PATCH and FETCH Methods for the Constrained Application Protocol (CoAP)
- [RFC 9175](https://datatracker.ietf.org/doc/html/rfc9175): CoAP: Echo, Request-Tag, and Token Processing

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
minicoap = "0.3"
```

For embedded debugging with `defmt`:

```toml
[dependencies]
minicoap = { version = "0.3", features = ["defmt"] }
```

## Usage

### Building Messages

Build a confirmable GET for `/temperature/sensor` in a caller-owned buffer.

```rust
use minicoap::{CoapBuildError, MessageBuilder, MessageType, OptionNumber, RequestCode};

fn main() -> Result<(), CoapBuildError> {
    let mut buffer = [0u8; 128];
    let packet = MessageBuilder::new(&mut buffer)?
        .request(MessageType::Confirmable, RequestCode::Get)
        .message_id(0x1234)
        .token(&[1, 2, 3, 4])?
        .option(OptionNumber::UriPath, b"temperature")?
        .option(OptionNumber::UriPath, b"sensor")?
        .no_payload()
        .build();

    assert_eq!(&packet[..4], &[0x44, 0x01, 0x12, 0x34]);
    Ok(())
}
```

### Parsing Messages

The token, option values, and payload borrow from the received datagram.

```rust
use minicoap::{ContentFormat, Message, OptionNumber};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Content response with a zero-length Content-Format value (text/plain).
    let received = [0x60, 0x45, 0x12, 0x34, 0xc0, 0xff, b'O', b'K'];
    let message = Message::parse(&received)?;

    for option in message.options {
        match option.number {
            OptionNumber::UriPath => println!("URI path segment: {}", option.as_str()?),
            OptionNumber::ContentFormat => {
                let value = option.as_uint().ok_or("invalid integer option")?;
                let format = ContentFormat::from(u16::try_from(value)?);
                assert_eq!(format, ContentFormat::TextPlain);
            }
            _ => {}
        }
    }
    assert_eq!(message.payload, Some(b"OK".as_slice()));
    Ok(())
}
```

### Working with Options

Append options in ascending number order. To add repeated options in a loop,
keep the builder returned by each call.

```rust
use minicoap::{CoapBuildError, MessageBuilder, MessageType, OptionNumber, RequestCode};

fn main() -> Result<(), CoapBuildError> {
    let mut buffer = [0; 128];
    let mut builder = MessageBuilder::new(&mut buffer)?
        .request(MessageType::Confirmable, RequestCode::Get)
        .message_id(1)
        .no_token()?
        .option(OptionNumber::Etag, &[1, 2, 3, 4])?;

    for segment in ["api", "v1"] {
        builder = builder.option_string(OptionNumber::UriPath, segment)?;
    }
    let packet = builder.option_uint(OptionNumber::Accept, 50u16)?.no_payload().build();
    assert!(packet.ends_with(&[50]));
    Ok(())
}
```

### Response Codes

Build a text response to a tokenless confirmable GET with message ID `0x1234`.

```rust
use minicoap::{CoapBuildError, ContentFormat, MessageBuilder, MessageType, OptionNumber, ResponseCode};

fn main() -> Result<(), CoapBuildError> {
    let mut buffer = [0; 128];
    let response = MessageBuilder::new(&mut buffer)?
        .response(MessageType::Acknowledgement, ResponseCode::Content)
        .message_id(0x1234)
        .no_token()?
        .option_uint(OptionNumber::ContentFormat, ContentFormat::TextPlain)?
        .payload(b"Hello, CoAP!")?
        .build();

    assert!(response.ends_with(b"Hello, CoAP!"));
    Ok(())
}
```

## License

This project is dual-licensed under MIT or Apache-2.0.
