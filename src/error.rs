#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(missing_docs)]
pub enum CoapBuildError {
    BufferTooSmall,
    TokenTooLong(usize),
    PayloadMarkerWithoutPayload,
    OptionNumberOutOfOrder,
}

impl core::fmt::Display for CoapBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoapBuildError::BufferTooSmall => write!(f, "Buffer too small"),
            CoapBuildError::TokenTooLong(len) => {
                write!(f, "Token too long (expected <= 8, got {})", len)
            }
            CoapBuildError::PayloadMarkerWithoutPayload => {
                write!(f, "Payload marker without payload")
            }
            CoapBuildError::OptionNumberOutOfOrder => write!(f, "Option number out of order"),
        }
    }
}

impl core::error::Error for CoapBuildError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(missing_docs)]
pub enum CoapParseError {
    MessageTooShort,
    UnknownVersion(u8),
    InvalidTokenLength(usize),
    InvalidOptionDelta,
    InvalidOptionLength,
    EmptyMessageWithData,
    PayloadMarkerWithoutPayload,
}

impl core::fmt::Display for CoapParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoapParseError::MessageTooShort => write!(f, "Message too short"),
            CoapParseError::UnknownVersion(v) => write!(f, "Unknown CoAP version: {}", v),
            CoapParseError::InvalidTokenLength(len) => {
                write!(f, "Invalid token length (expected 0-8, got {})", len)
            }
            CoapParseError::InvalidOptionDelta => write!(f, "Invalid option delta (15)"),
            CoapParseError::InvalidOptionLength => write!(f, "Invalid option length (15)"),
            CoapParseError::EmptyMessageWithData => {
                write!(f, "Empty message (code 0.00) contains data after header")
            }
            CoapParseError::PayloadMarkerWithoutPayload => {
                write!(f, "Payload marker present but no payload data")
            }
        }
    }
}

impl core::error::Error for CoapParseError {}
