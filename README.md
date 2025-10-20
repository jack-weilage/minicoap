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
- [RFC 8132](https://datatracker.ietf.org/doc/html/rfc8132): PATCH and FETCH Methods for the Constrained Application Protocol (CoAP)
- [RFC 9175](https://datatracker.ietf.org/doc/html/rfc9175): CoAP: Echo, Request-Tag, and Token Processing

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
minicoap = "0.1.0"
```

For embedded debugging with `defmt`:

```toml
[dependencies]
minicoap = { version = "0.1.0", features = ["defmt"] }
```

## Usage

### Building Messages

The library provides a type-safe builder API that ensures messages are constructed correctly at compile time:

```rust
use minicoap::{MessageBuilder, MessageType, RequestCode, OptionNumber};

let mut buffer = [0u8; 128];

// Build a GET request
let packet = MessageBuilder::new(&mut buffer)?
    .request(MessageType::Confirmable, RequestCode::Get)
    .message_id(0x1234)
    .token(&[0x01, 0x02, 0x03, 0x04])?
    .option(OptionNumber::UriPath, b"temperature")?
    .option(OptionNumber::UriPath, b"sensor")?
    .no_payload()
    .build();

// Send packet over UDP...
```

### Parsing Messages

Parse received CoAP messages with zero-copy parsing:

```rust
use minicoap::{Message, OptionNumber, ContentFormat};

// Receive buffer from UDP...
let received = [0x40, 0x01, 0x12, 0x34];

let message = Message::parse(&received)?;

println!("Version: {:?}", message.version);
println!("Type: {:?}", message.message_type);
println!("Code: {}.{:02}", message.code_class(), message.code_detail());
println!("Message ID: {}", message.message_id);

// Iterate over options
for option in message.options {
    match option.number {
        OptionNumber::UriPath => {
            println!("URI Path: {}", option.as_str()?);
        }
        OptionNumber::ContentFormat => {
            let format: ContentFormat = (option.as_uint()? as u16).into();
            println!("Content Format: {:?}", format);
        }
        _ => {}
    }
}

if let Some(payload) = message.payload {
    println!("Payload: {:?}", payload);
}
```

### Working with Options

Options can be added with different value types:

```rust
// String options
builder.option_string(OptionNumber::UriPath, "api")?;
builder.option_string(OptionNumber::UriPath, "v1")?;

// Integer options (automatically minimally encoded)
builder.option_uint(OptionNumber::MaxAge, 60u32)?;
builder.option_uint(OptionNumber::ContentFormat, 50u16)?;

// Raw byte options
builder.option(OptionNumber::Etag, &[0x01, 0x02, 0x03, 0x04])?;
```

### Response Codes

The library provides comprehensive response code support:

```rust
use minicoap::{ResponseCode, MessageType, OptionNumber, ContentFormat};

let response = MessageBuilder::new(&mut buffer)?
    .response(MessageType::Acknowledgement, ResponseCode::Content)
    .message_id(0x1234)
    .no_token()?
    .option_uint(OptionNumber::ContentFormat, ContentFormat::TextPlain)?
    .payload(b"Hello, CoAP!")?
    .build();
```

## License

This project is dual-licensed under MIT or Apache-2.0.
