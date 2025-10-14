use crate::error::CoapParseError;
use crate::{MessageType, OptionNumber, Version};

type ParseResult<T> = core::result::Result<T, CoapParseError>;

/// Parsed CoAP message representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Message<'a> {
    /// CoAP protocol version
    pub version: Version,
    /// Message type (Confirmable, Non-confirmable, Acknowledgement, Reset)
    pub message_type: MessageType,
    /// Token bytes for request/response matching
    pub token: &'a [u8],
    /// Message code (method for requests, response code for responses)
    pub code: u8,
    /// Message ID for duplicate detection and message correlation
    pub message_id: u16,
    /// Collection of options in the message
    pub options: CoapOptions<'a>,
    /// Optional payload data
    pub payload: Option<&'a [u8]>,
}

impl<'a> Message<'a> {
    /// Parse a CoAP message from a byte buffer
    pub fn parse(buffer: &'a [u8]) -> ParseResult<Self> {
        if buffer.len() < 4 {
            return Err(CoapParseError::MessageTooShort);
        }

        let version_raw = (buffer[0] >> 6) & 0b11;
        let version = match version_raw {
            1 => Version::V1,
            _ => return Err(CoapParseError::UnknownVersion(version_raw)),
        };

        let message_type_raw = (buffer[0] >> 4) & 0b11;
        let message_type = match message_type_raw {
            0 => MessageType::Confirmable,
            1 => MessageType::NonConfirmable,
            2 => MessageType::Acknowledgement,
            3 => MessageType::Reset,
            _ => unreachable!(),
        };

        let token_len = (buffer[0] & 0x0F) as usize;
        if token_len > 8 {
            return Err(CoapParseError::InvalidTokenLength(token_len));
        }

        let code = buffer[1];

        let message_id = u16::from_be_bytes([buffer[2], buffer[3]]);

        if buffer.len() < 4 + token_len {
            return Err(CoapParseError::MessageTooShort);
        }

        let token = &buffer[4..4 + token_len];

        let mut offset = 4 + token_len;

        if code == 0 && buffer.len() > offset {
            return Err(CoapParseError::EmptyMessageWithData);
        }

        let options_start = offset;
        let mut options_end = offset;
        let mut payload_start = None;

        while offset < buffer.len() {
            if buffer[offset] == 0xFF {
                payload_start = Some(offset + 1);
                options_end = offset;
                break;
            }

            let delta = (buffer[offset] >> 4) & 0x0F;
            let length = buffer[offset] & 0x0F;

            if delta == 15 {
                return Err(CoapParseError::InvalidOptionDelta);
            }

            offset += 1;

            let delta_ext_len = match delta {
                13 => 1,
                14 => 2,
                _ => 0,
            };

            let length_ext_len = match length {
                13 => 1,
                14 => 2,
                15 => return Err(CoapParseError::InvalidOptionLength),
                _ => 0,
            };

            if offset + delta_ext_len + length_ext_len > buffer.len() {
                return Err(CoapParseError::MessageTooShort);
            }

            offset += delta_ext_len;

            let value_len = match length {
                0..=12 => length as usize,
                13 => buffer[offset] as usize + 13,
                14 => u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) as usize + 269,
                _ => return Err(CoapParseError::InvalidOptionLength),
            };

            offset += length_ext_len;

            if offset + value_len > buffer.len() {
                return Err(CoapParseError::MessageTooShort);
            }

            offset += value_len;
            options_end = offset;
        }

        let options = CoapOptions {
            data: &buffer[options_start..options_end],
        };

        let payload = payload_start
            .map(|start| {
                if start >= buffer.len() {
                    return Err(CoapParseError::PayloadMarkerWithoutPayload);
                }

                Ok(&buffer[start..])
            })
            .transpose()?;

        Ok(Message {
            version,
            message_type,
            token,
            code,
            message_id,
            options,
            payload,
        })
    }

    /// Extract the class portion of the code (upper 3 bits)
    pub fn code_class(&self) -> u8 {
        self.code >> 5
    }

    /// Extract the detail portion of the code (lower 5 bits)
    pub fn code_detail(&self) -> u8 {
        self.code & 0x1F
    }

    /// Check if this message is a request
    pub fn is_request(&self) -> bool {
        self.code_class() == 0 && self.code_detail() != 0
    }

    /// Check if this message is a response
    pub fn is_response(&self) -> bool {
        matches!(self.code_class(), 2 | 4 | 5)
    }

    /// Check if this message is empty (code 0.00)
    pub fn is_empty(&self) -> bool {
        self.code == 0
    }
}

/// Collection of CoAP options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CoapOptions<'a> {
    data: &'a [u8],
}

impl<'a> IntoIterator for CoapOptions<'a> {
    type Item = CoapOption<'a>;
    type IntoIter = OptionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OptionIterator {
            data: self.data,
            offset: 0,
            current_option_number: 0,
        }
    }
}

impl<'a> IntoIterator for &CoapOptions<'a> {
    type Item = CoapOption<'a>;
    type IntoIter = OptionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OptionIterator {
            data: self.data,
            offset: 0,
            current_option_number: 0,
        }
    }
}

/// A single CoAP option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CoapOption<'a> {
    /// Option number
    pub number: OptionNumber,
    /// Option value bytes
    pub value: &'a [u8],
}

impl<'a> CoapOption<'a> {
    /// Interpret the option value as an unsigned integer (up to 8 bytes)
    pub fn as_uint(&self) -> Option<u64> {
        match self.value.len() {
            0 => Some(0),
            1 => Some(self.value[0] as u64),
            2 => Some(u16::from_be_bytes([self.value[0], self.value[1]]) as u64),
            3 => Some(u32::from_be_bytes([0, self.value[0], self.value[1], self.value[2]]) as u64),
            4 => Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]) as u64),
            5 => Some(u64::from_be_bytes([
                0,
                0,
                0,
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
                self.value[4],
            ])),
            6 => Some(u64::from_be_bytes([
                0,
                0,
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
                self.value[4],
                self.value[5],
            ])),
            7 => Some(u64::from_be_bytes([
                0,
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
                self.value[4],
                self.value[5],
                self.value[6],
            ])),
            8 => Some(u64::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
                self.value[4],
                self.value[5],
                self.value[6],
                self.value[7],
            ])),
            _ => None,
        }
    }

    /// Interpret the option value as a UTF-8 string
    pub fn as_str(&self) -> Result<&'a str, core::str::Utf8Error> {
        core::str::from_utf8(self.value)
    }

    /// Check if this option is critical
    pub fn is_critical(&self) -> bool {
        self.number.is_critical()
    }

    /// Check if this option is unsafe to forward
    pub fn is_unsafe(&self) -> bool {
        self.number.is_unsafe()
    }

    /// Check if this option should not be part of the cache key
    pub fn is_no_cache_key(&self) -> bool {
        self.number.is_no_cache_key()
    }
}

/// Iterator over CoAP options
pub struct OptionIterator<'a> {
    data: &'a [u8],
    offset: usize,
    current_option_number: u16,
}

impl<'a> Iterator for OptionIterator<'a> {
    type Item = CoapOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let header_byte = self.data[self.offset];
        let delta = (header_byte >> 4) & 0x0F;
        let length = header_byte & 0x0F;

        if delta == 15 {
            return None;
        }

        self.offset += 1;

        let actual_delta = match delta {
            0..=12 => delta as u16,
            13 => {
                if self.offset >= self.data.len() {
                    return None;
                }
                let ext = self.data[self.offset] as u16;
                self.offset += 1;
                ext + 13
            }
            14 => {
                if self.offset + 1 >= self.data.len() {
                    return None;
                }
                let ext = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]);
                self.offset += 2;
                ext + 269
            }
            _ => return None,
        };

        self.current_option_number += actual_delta;

        let actual_length = match length {
            0..=12 => length as usize,
            13 => {
                if self.offset >= self.data.len() {
                    return None;
                }
                let ext = self.data[self.offset] as usize;
                self.offset += 1;
                ext + 13
            }
            14 => {
                if self.offset + 1 >= self.data.len() {
                    return None;
                }
                let ext = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]])
                    as usize;
                self.offset += 2;
                ext + 269
            }
            15 => return None,
            _ => unreachable!(),
        };

        if self.offset + actual_length > self.data.len() {
            return None;
        }

        let value = &self.data[self.offset..self.offset + actual_length];
        self.offset += actual_length;

        Some(CoapOption {
            number: OptionNumber::from(self.current_option_number),
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageBuilder, OptionNumber, RequestCode};

    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn parse_simple_get_request() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x1234)
            .no_token()
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        assert_eq!(message.version, Version::V1);
        assert_eq!(message.message_type, MessageType::Confirmable);
        assert_eq!(message.code, 0x01);
        assert_eq!(message.message_id, 0x1234);
        assert_eq!(message.token, &[]);
        assert!(message.payload.is_none());
        assert!(message.is_request());
        assert!(!message.is_response());
        assert!(!message.is_empty());
    }

    #[test]
    fn parse_request_with_token() {
        let mut buffer = [0; 128];
        let token = [0x12, 0x34, 0x56, 0x78];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0xABCD)
            .token(&token)
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        assert_eq!(message.token, &token);
        assert_eq!(message.message_id, 0xABCD);
    }

    #[test]
    fn parse_request_with_payload() {
        let mut buffer = [0; 128];
        let payload_data = b"Hello, CoAP!";

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::NonConfirmable, RequestCode::Post)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .payload(payload_data)
            .unwrap()
            .build();

        let message = Message::parse(packet).unwrap();

        assert_eq!(message.message_type, MessageType::NonConfirmable);
        assert_eq!(message.payload, Some(&payload_data[..]));
    }

    #[test]
    fn parse_request_with_options() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x5678)
            .no_token()
            .unwrap()
            .option(OptionNumber::UriPath, b"temperature")
            .unwrap()
            .option(OptionNumber::UriPath, b"sensor")
            .unwrap()
            .option(OptionNumber::Accept, &[0])
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        let options: Vec<_> = message.options.into_iter().collect();
        assert_eq!(options.len(), 3);

        assert_eq!(options[0].number, OptionNumber::UriPath);
        assert_eq!(options[0].value, b"temperature");

        assert_eq!(options[1].number, OptionNumber::UriPath);
        assert_eq!(options[1].value, b"sensor");

        assert_eq!(options[2].number, OptionNumber::Accept);
        assert_eq!(options[2].value, &[0]);
    }

    #[test]
    fn parse_option_find() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::UriPath, b"test")
            .unwrap()
            .option(OptionNumber::ContentFormat, &[0])
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        let uri_path = message
            .options
            .into_iter()
            .find(|opt| opt.number == OptionNumber::UriPath)
            .map(|opt| opt.value);
        assert_eq!(uri_path, Some(&b"test"[..]));

        let content_format = message
            .options
            .into_iter()
            .find(|opt| opt.number == OptionNumber::ContentFormat)
            .map(|opt| opt.value);
        assert_eq!(content_format, Some(&[0][..]));

        let missing = message
            .options
            .into_iter()
            .find(|opt| opt.number == OptionNumber::MaxAge)
            .map(|opt| opt.value);
        assert_eq!(missing, None);
    }

    #[test]
    fn parse_option_find_all() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::UriPath, b"api")
            .unwrap()
            .option(OptionNumber::UriPath, b"v1")
            .unwrap()
            .option(OptionNumber::UriPath, b"resource")
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        let paths: Vec<_> = message
            .options
            .into_iter()
            .filter(|opt| opt.number == OptionNumber::UriPath)
            .map(|opt| opt.value)
            .collect();
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], b"api");
        assert_eq!(paths[1], b"v1");
        assert_eq!(paths[2], b"resource");
    }

    #[test]
    fn parse_option_as_uint() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::MaxAge, &60u32.to_be_bytes())
            .unwrap()
            .option(OptionNumber::Accept, &[0])
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        let max_age_opt = message
            .options
            .into_iter()
            .find(|o| o.number == OptionNumber::MaxAge)
            .unwrap();
        assert_eq!(max_age_opt.as_uint(), Some(60));

        let accept_opt = message
            .options
            .into_iter()
            .find(|o| o.number == OptionNumber::Accept)
            .unwrap();
        assert_eq!(accept_opt.as_uint(), Some(0));
    }

    #[test]
    fn parse_option_as_str() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::UriPath, b"hello")
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        let uri_path_opt = message
            .options
            .into_iter()
            .find(|o| o.number == OptionNumber::UriPath)
            .unwrap();
        assert_eq!(uri_path_opt.as_str(), Ok("hello"));
    }

    #[test]
    fn parse_empty_message() {
        let mut buffer = [0; 128];

        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .empty(MessageType::Acknowledgement)
            .message_id(0xFFFF)
            .no_token()
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();

        assert_eq!(message.code, 0);
        assert!(message.is_empty());
        assert!(!message.is_request());
        assert!(!message.is_response());
    }

    #[test]
    fn parse_message_too_short() {
        let buffer = [0x40, 0x01, 0x00];
        let result = Message::parse(&buffer);
        assert!(matches!(result, Err(CoapParseError::MessageTooShort)));
    }

    #[test]
    fn parse_invalid_token_length() {
        let buffer = [0x4F, 0x01, 0x00, 0x00];
        let result = Message::parse(&buffer);
        assert!(matches!(
            result,
            Err(CoapParseError::InvalidTokenLength(15))
        ));
    }

    #[test]
    fn parse_unknown_version() {
        let buffer = [0x00, 0x01, 0x00, 0x00];
        let result = Message::parse(&buffer);
        assert!(matches!(result, Err(CoapParseError::UnknownVersion(0))));
    }

    #[test]
    fn parse_content_format() {
        let mut buffer = [0; 128];

        use crate::ContentFormat;

        // Test with TextPlain (0)
        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Post)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::ContentFormat, &[0])
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();
        let content_format_opt = message
            .options
            .into_iter()
            .find(|opt| opt.number == OptionNumber::ContentFormat)
            .unwrap();

        assert_eq!(content_format_opt.as_uint(), Some(0));
        let cf: ContentFormat = (content_format_opt.as_uint().unwrap() as u16).into();
        assert_eq!(cf, ContentFormat::TextPlain);

        // Test with ApplicationJson (50)
        let mut buffer = [0; 128];
        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Post)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::ContentFormat, &[50])
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();
        let content_format_opt = message
            .options
            .into_iter()
            .find(|opt| opt.number == OptionNumber::ContentFormat)
            .unwrap();

        assert_eq!(content_format_opt.as_uint(), Some(50));
        let cf: ContentFormat = (content_format_opt.as_uint().unwrap() as u16).into();
        assert_eq!(cf, ContentFormat::ApplicationJson);

        // Test with unknown content format
        let mut buffer = [0; 128];
        let packet = MessageBuilder::new(&mut buffer)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Post)
            .message_id(0x0001)
            .no_token()
            .unwrap()
            .option(OptionNumber::ContentFormat, &[99])
            .unwrap()
            .no_payload()
            .build();

        let message = Message::parse(packet).unwrap();
        let content_format_opt = message
            .options
            .into_iter()
            .find(|opt| opt.number == OptionNumber::ContentFormat)
            .unwrap();

        assert_eq!(content_format_opt.as_uint(), Some(99));
        let cf: ContentFormat = (content_format_opt.as_uint().unwrap() as u16).into();
        assert_eq!(cf, ContentFormat::Unknown(99));
    }
}
