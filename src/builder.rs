use core::marker::PhantomData;

use crate::{MessageType, RequestCode, ResponseCode, Version, coap_code, error::CoapBuildError};

type BuilderResult<'buf, T> = core::result::Result<MessageBuilder<'buf, T>, CoapBuildError>;

/// Converts an unsigned integer to minimal byte representation (big-endian, no leading zeros).
/// According to RFC 7252 Section 3.2, 0 is represented as an empty slice.
/// Returns a tuple of (byte array, start index) where the meaningful bytes are from start..8.
fn uint_to_minimal_bytes(value: u64) -> ([u8; 8], usize) {
    if value == 0 {
        return ([0; 8], 8); // Empty slice: start at end
    }

    let bytes = value.to_be_bytes();
    // Count leading zero bytes
    let leading_zeros = (value.leading_zeros() / 8) as usize;

    (bytes, leading_zeros)
}

/// State for receiving the buffer.
pub struct NeedsBuffer;
/// State for constructing the header.
pub struct NeedsHeader;
/// State for adding the message ID.
pub struct NeedsMessageId;
/// State for adding the token and setting the token length.
pub struct NeedsToken;
/// State for adding options and/or payload.
pub struct NeedsPayload;
/// State for completing the packet.
pub struct Complete;

/// Builder for CoAP messages.
pub struct MessageBuilder<'buf, State> {
    buffer: &'buf mut [u8],
    offset: usize,
    last_option_number: u16,
    _state: PhantomData<State>,
}

impl<'buf> MessageBuilder<'buf, NeedsBuffer> {
    /// Create a new packet builder with the given buffer. The buffer must be at least 4 bytes long.
    pub fn new(buffer: &'buf mut [u8]) -> BuilderResult<'buf, NeedsHeader> {
        if buffer.len() < 4 {
            return Err(CoapBuildError::BufferTooSmall);
        }

        Ok(MessageBuilder {
            buffer,
            offset: 0,
            last_option_number: 0,
            _state: PhantomData,
        })
    }
}

impl<'buf> MessageBuilder<'buf, NeedsHeader> {
    /// Construct a header for a CoAP packet.
    pub fn header(
        mut self,
        msg_type: MessageType,
        code: impl Into<u8>,
    ) -> MessageBuilder<'buf, NeedsMessageId> {
        // ver 0..2 | msg_type 2..4 | token_len 4..8 (set later)
        self.buffer[0] = (u8::from(Version::V1) << 6) | (u8::from(msg_type)) << 4;
        self.buffer[1] = code.into();

        self.offset = 2;

        MessageBuilder {
            buffer: self.buffer,
            offset: self.offset,
            last_option_number: self.last_option_number,
            _state: PhantomData,
        }
    }

    /// Convenience method for constructing a request packet.
    pub fn request(
        self,
        msg_type: MessageType,
        code: RequestCode,
    ) -> MessageBuilder<'buf, NeedsMessageId> {
        self.header(msg_type, code)
    }

    /// Convenience method for constructing a response packet.
    pub fn response(
        self,
        msg_type: MessageType,
        code: ResponseCode,
    ) -> MessageBuilder<'buf, NeedsMessageId> {
        self.header(msg_type, code)
    }

    /// Convenience method for constructing an empty packet.
    pub fn empty(self, msg_type: MessageType) -> MessageBuilder<'buf, NeedsMessageId> {
        self.header(msg_type, coap_code!(0, 00))
    }

    /// Convenience method for constructing a ping request.
    pub fn ping(self) -> MessageBuilder<'buf, NeedsMessageId> {
        self.header(MessageType::Confirmable, coap_code!(0, 00))
    }
}

impl<'buf> MessageBuilder<'buf, NeedsMessageId> {
    /// Set the message ID for the packet.
    pub fn message_id(mut self, id: u16) -> MessageBuilder<'buf, NeedsToken> {
        self.buffer[self.offset..self.offset + 2].copy_from_slice(&id.to_be_bytes());
        self.offset += 2;

        MessageBuilder {
            buffer: self.buffer,
            offset: self.offset,
            last_option_number: self.last_option_number,
            _state: PhantomData,
        }
    }
}

impl<'buf> MessageBuilder<'buf, NeedsToken> {
    /// Add a token of between 0 and 8 bytes.
    pub fn token(mut self, token: &[u8]) -> BuilderResult<'buf, NeedsPayload> {
        let token_len = token.len();
        if token_len > 8 {
            return Err(CoapBuildError::TokenTooLong(token_len));
        }

        if self.offset + token_len > self.buffer.len() {
            return Err(CoapBuildError::BufferTooSmall);
        }

        // Update TKL in header.
        self.buffer[0] |= token_len as u8 & 0x0F;

        self.buffer[self.offset..self.offset + token_len].copy_from_slice(token);
        self.offset += token_len;

        Ok(MessageBuilder {
            buffer: self.buffer,
            offset: self.offset,
            last_option_number: self.last_option_number,
            _state: PhantomData,
        })
    }

    /// Skip adding a token (uses a zero-length token)
    pub fn no_token(self) -> BuilderResult<'buf, NeedsPayload> {
        // TKL is already set to 0, just transition state.

        Ok(MessageBuilder {
            buffer: self.buffer,
            offset: self.offset,
            last_option_number: self.last_option_number,
            _state: PhantomData,
        })
    }
}

impl<'buf> MessageBuilder<'buf, NeedsPayload> {
    /// Add an option to the packet.
    pub fn option(
        mut self,
        option_number: impl Into<u16>,
        value: &[u8],
    ) -> BuilderResult<'buf, NeedsPayload> {
        let option_number = option_number.into();
        let delta = option_number - self.last_option_number;

        let (delta_field, delta_ext) = match delta {
            0..=12 => (delta as u8, &[][..]),
            13..=268 => (13, &((delta - 13) as u8).to_be_bytes()[..]),
            269.. => (14, &(delta - 269).to_be_bytes()[..]),
        };

        let (length_field, length_ext) = match value.len() {
            0..=12 => (value.len() as u8, &[][..]),
            13..=268 => (13, &((value.len() - 13) as u8).to_be_bytes()[..]),
            269.. => (14, &(value.len() - 269).to_be_bytes()[..]),
        };

        let option_header_len = 1 + delta_ext.len() + length_ext.len();
        let option_len = option_header_len + value.len();

        if self.offset + option_len > self.buffer.len() {
            return Err(CoapBuildError::BufferTooSmall);
        }

        // Write the header byte
        self.buffer[self.offset] = (delta_field << 4) | length_field;
        self.offset += 1;

        // Write the delta extension. If it's empty, nothing will be written.
        self.buffer[self.offset..self.offset + delta_ext.len()].copy_from_slice(delta_ext);
        self.offset += delta_ext.len();

        // Write the length extension. If it's empty, nothing will be written.
        self.buffer[self.offset..self.offset + length_ext.len()].copy_from_slice(length_ext);
        self.offset += length_ext.len();

        // Write the value
        self.buffer[self.offset..self.offset + value.len()].copy_from_slice(value);
        self.offset += value.len();

        self.last_option_number = option_number;

        Ok(self)
    }

    /// Add an option with a UTF8 string value.
    pub fn option_string(
        self,
        option_number: impl Into<u16>,
        value: &str,
    ) -> BuilderResult<'buf, NeedsPayload> {
        self.option(option_number, value.as_bytes())
    }

    /// Add an option with an unsigned integer value.
    /// The integer will be encoded with minimal bytes according to RFC 7252 Section 3.2.
    /// The value 0 is encoded as an empty option value (zero-length).
    pub fn option_uint(
        self,
        option_number: impl Into<u16>,
        value: impl Into<u64>,
    ) -> BuilderResult<'buf, NeedsPayload> {
        let value = value.into();
        let (bytes, start) = uint_to_minimal_bytes(value);
        self.option(option_number, &bytes[start..])
    }

    /// Add a payload to the packet.
    pub fn payload(mut self, payload: &[u8]) -> BuilderResult<'buf, Complete> {
        if payload.is_empty() {
            return Err(CoapBuildError::PayloadMarkerWithoutPayload);
        }

        if self.offset + 1 + payload.len() > self.buffer.len() {
            return Err(CoapBuildError::BufferTooSmall);
        }

        // Write payload marker
        self.buffer[self.offset] = 0xFF;
        self.offset += 1;

        // Write payload
        self.buffer[self.offset..self.offset + payload.len()].copy_from_slice(payload);
        self.offset += payload.len();

        Ok(MessageBuilder {
            buffer: self.buffer,
            offset: self.offset,
            last_option_number: self.last_option_number,
            _state: PhantomData,
        })
    }

    /// Skips adding a payload to the packet.
    pub fn no_payload(self) -> MessageBuilder<'buf, Complete> {
        MessageBuilder {
            buffer: self.buffer,
            offset: self.offset,
            last_option_number: self.last_option_number,
            _state: PhantomData,
        }
    }
}

impl<'buf> MessageBuilder<'buf, Complete> {
    /// Build the packet.
    pub fn build(self) -> &'buf [u8] {
        &self.buffer[..self.offset]
    }

    /// Returns the length of the packet.
    pub fn len(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::OptionNumber;

    #[test]
    fn test_no_token() -> Result<(), CoapBuildError> {
        let mut tx_buf = [0; 128];

        let packet = MessageBuilder::new(&mut tx_buf)?
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0)
            .no_token()?
            .no_payload()
            .build();

        assert_eq!(packet.len(), 4);
        assert_eq!(packet, &[0x40, 0x01, 0x00, 0x00]);

        Ok(())
    }

    #[test]
    fn test_uint_to_minimal_bytes() {
        // Test 0 - should be empty
        let (bytes, start) = uint_to_minimal_bytes(0);
        assert_eq!(&bytes[start..], &[]);

        // Test 1 - should be 1 byte
        let (bytes, start) = uint_to_minimal_bytes(1);
        assert_eq!(&bytes[start..], &[1]);

        // Test 255 - should be 1 byte
        let (bytes, start) = uint_to_minimal_bytes(255);
        assert_eq!(&bytes[start..], &[255]);

        // Test 256 - should be 2 bytes
        let (bytes, start) = uint_to_minimal_bytes(256);
        assert_eq!(&bytes[start..], &[1, 0]);

        // Test 65535 - should be 2 bytes
        let (bytes, start) = uint_to_minimal_bytes(65535);
        assert_eq!(&bytes[start..], &[255, 255]);

        // Test 65536 - should be 3 bytes
        let (bytes, start) = uint_to_minimal_bytes(65536);
        assert_eq!(&bytes[start..], &[1, 0, 0]);

        // Test max u32 - should be 4 bytes
        let (bytes, start) = uint_to_minimal_bytes(u32::MAX as u64);
        assert_eq!(&bytes[start..], &[255, 255, 255, 255]);

        // Test a large u64 value
        let (bytes, start) = uint_to_minimal_bytes(0x0102030405060708);
        assert_eq!(&bytes[start..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_option_uint_zero() -> Result<(), CoapBuildError> {
        let mut tx_buf = [0; 128];

        let packet = MessageBuilder::new(&mut tx_buf)?
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x1234)
            .no_token()?
            .option_uint(OptionNumber::Accept, 0u8)?
            .no_payload()
            .build();

        // Parse the packet to verify
        use crate::parser::Message;
        let msg = Message::parse(packet).unwrap();
        let accept_opt = msg
            .options
            .into_iter()
            .find(|o| o.number == OptionNumber::Accept)
            .unwrap();

        // RFC 7252 Section 3.2: 0 is represented as empty
        assert_eq!(accept_opt.value, &[]);
        assert_eq!(accept_opt.as_uint(), Some(0));

        Ok(())
    }

    #[test]
    fn test_option_uint_small_values() -> Result<(), CoapBuildError> {
        let mut tx_buf = [0; 128];

        let packet = MessageBuilder::new(&mut tx_buf)?
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x1234)
            .no_token()?
            .option_uint(OptionNumber::MaxAge, 60u32)?
            .no_payload()
            .build();

        use crate::parser::Message;
        let msg = Message::parse(packet).unwrap();
        let max_age_opt = msg
            .options
            .into_iter()
            .find(|o| o.number == OptionNumber::MaxAge)
            .unwrap();

        assert_eq!(max_age_opt.as_uint(), Some(60));

        Ok(())
    }

    #[test]
    fn test_option_uint_various_types() -> Result<(), CoapBuildError> {
        let mut tx_buf = [0; 128];

        // Test with u8
        let packet = MessageBuilder::new(&mut tx_buf)?
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x1234)
            .no_token()?
            .option_uint(OptionNumber::Accept, 50u8)?
            .no_payload()
            .build();

        use crate::parser::Message;
        let msg = Message::parse(packet).unwrap();
        let opt = msg.options.into_iter().next().unwrap();
        assert_eq!(opt.as_uint(), Some(50));

        // Test with u16
        let mut tx_buf = [0; 128];
        let packet = MessageBuilder::new(&mut tx_buf)?
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x1234)
            .no_token()?
            .option_uint(OptionNumber::UriPort, 8080u16)?
            .no_payload()
            .build();

        let msg = Message::parse(packet).unwrap();
        let opt = msg.options.into_iter().next().unwrap();
        assert_eq!(opt.as_uint(), Some(8080));

        // Test with u32
        let mut tx_buf = [0; 128];
        let packet = MessageBuilder::new(&mut tx_buf)?
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x1234)
            .no_token()?
            .option_uint(OptionNumber::MaxAge, 86400u32)?
            .no_payload()
            .build();

        let msg = Message::parse(packet).unwrap();
        let opt = msg.options.into_iter().next().unwrap();
        assert_eq!(opt.as_uint(), Some(86400));

        Ok(())
    }

    #[test]
    fn test_option_uint_roundtrip() -> Result<(), CoapBuildError> {
        let test_values = [
            0u64, 1, 127, 128, 255, 256, 65535, 65536, 16777215, 16777216,
        ];

        for &value in &test_values {
            let mut tx_buf = [0; 128];
            let packet = MessageBuilder::new(&mut tx_buf)?
                .request(MessageType::Confirmable, RequestCode::Get)
                .message_id(0x1234)
                .no_token()?
                .option_uint(OptionNumber::MaxAge, value)?
                .no_payload()
                .build();

            use crate::parser::Message;
            let msg = Message::parse(packet).unwrap();
            let opt = msg
                .options
                .into_iter()
                .find(|o| o.number == OptionNumber::MaxAge)
                .unwrap();

            assert_eq!(opt.as_uint(), Some(value), "Failed for value {}", value);
        }

        Ok(())
    }
}
