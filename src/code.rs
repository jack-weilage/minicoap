use crate::{RequestCode, ResponseCode};
use core::fmt;

/// A CoAP message code. Every wire byte has a representation, including extension codes.
///
/// ```
/// use minicoap::{Code, Message, MessageBuilder, MessageType};
///
/// let mut buffer = [0; 16];
/// let packet = MessageBuilder::new(&mut buffer)?
///     .header(MessageType::Confirmable, Code::GET)
///     .message_id(42)
///     .no_token()?
///     .no_payload()
///     .build();
/// let message = Message::parse(packet)?;
/// assert!(matches!(message.code, Code::GET));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct Code(u8);

impl Code {
    /// Empty message (0.00).
    pub const EMPTY: Self = Self(0);
    /// [Get](RequestCode::Get) (0.01).
    pub const GET: Self = Self(RequestCode::Get as u8);
    /// [Post](RequestCode::Post) (0.02).
    pub const POST: Self = Self(RequestCode::Post as u8);
    /// [Put](RequestCode::Put) (0.03).
    pub const PUT: Self = Self(RequestCode::Put as u8);
    /// [Delete](RequestCode::Delete) (0.04).
    pub const DELETE: Self = Self(RequestCode::Delete as u8);
    /// [Fetch](RequestCode::Fetch) (0.05).
    pub const FETCH: Self = Self(RequestCode::Fetch as u8);
    /// [Patch](RequestCode::Patch) (0.06).
    pub const PATCH: Self = Self(RequestCode::Patch as u8);
    /// [IPatch](RequestCode::IPatch) (0.07).
    pub const IPATCH: Self = Self(RequestCode::IPatch as u8);
    /// [Created](ResponseCode::Created) (2.01).
    pub const CREATED: Self = Self(ResponseCode::Created as u8);
    /// [Deleted](ResponseCode::Deleted) (2.02).
    pub const DELETED: Self = Self(ResponseCode::Deleted as u8);
    /// [Valid](ResponseCode::Valid) (2.03).
    pub const VALID: Self = Self(ResponseCode::Valid as u8);
    /// [Changed](ResponseCode::Changed) (2.04).
    pub const CHANGED: Self = Self(ResponseCode::Changed as u8);
    /// [Content](ResponseCode::Content) (2.05).
    pub const CONTENT: Self = Self(ResponseCode::Content as u8);
    /// [Continue](ResponseCode::Continue) (2.31).
    pub const CONTINUE: Self = Self(ResponseCode::Continue as u8);
    /// [BadRequest](ResponseCode::BadRequest) (4.00).
    pub const BAD_REQUEST: Self = Self(ResponseCode::BadRequest as u8);
    /// [Unauthorized](ResponseCode::Unauthorized) (4.01).
    pub const UNAUTHORIZED: Self = Self(ResponseCode::Unauthorized as u8);
    /// [BadOption](ResponseCode::BadOption) (4.02).
    pub const BAD_OPTION: Self = Self(ResponseCode::BadOption as u8);
    /// [RequestEntityIncomplete](ResponseCode::RequestEntityIncomplete) (4.08).
    pub const REQUEST_ENTITY_INCOMPLETE: Self = Self(ResponseCode::RequestEntityIncomplete as u8);
    /// [Conflict](ResponseCode::Conflict) (4.09).
    pub const CONFLICT: Self = Self(ResponseCode::Conflict as u8);
    /// [Forbidden](ResponseCode::Forbidden) (4.03).
    pub const FORBIDDEN: Self = Self(ResponseCode::Forbidden as u8);
    /// [NotFound](ResponseCode::NotFound) (4.04).
    pub const NOT_FOUND: Self = Self(ResponseCode::NotFound as u8);
    /// [MethodNotAllowed](ResponseCode::MethodNotAllowed) (4.05).
    pub const METHOD_NOT_ALLOWED: Self = Self(ResponseCode::MethodNotAllowed as u8);
    /// [NotAcceptable](ResponseCode::NotAcceptable) (4.06).
    pub const NOT_ACCEPTABLE: Self = Self(ResponseCode::NotAcceptable as u8);
    /// [PreconditionFailed](ResponseCode::PreconditionFailed) (4.12).
    pub const PRECONDITION_FAILED: Self = Self(ResponseCode::PreconditionFailed as u8);
    /// [RequestEntityTooLarge](ResponseCode::RequestEntityTooLarge) (4.13).
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self(ResponseCode::RequestEntityTooLarge as u8);
    /// [UnsupportedContentFormat](ResponseCode::UnsupportedContentFormat) (4.15).
    pub const UNSUPPORTED_CONTENT_FORMAT: Self = Self(ResponseCode::UnsupportedContentFormat as u8);
    /// [UnprocessableEntity](ResponseCode::UnprocessableEntity) (4.22).
    pub const UNPROCESSABLE_ENTITY: Self = Self(ResponseCode::UnprocessableEntity as u8);
    /// [InternalServerError](ResponseCode::InternalServerError) (5.00).
    pub const INTERNAL_SERVER_ERROR: Self = Self(ResponseCode::InternalServerError as u8);
    /// [NotImplemented](ResponseCode::NotImplemented) (5.01).
    pub const NOT_IMPLEMENTED: Self = Self(ResponseCode::NotImplemented as u8);
    /// [BadGateway](ResponseCode::BadGateway) (5.02).
    pub const BAD_GATEWAY: Self = Self(ResponseCode::BadGateway as u8);
    /// [ServiceUnavailable](ResponseCode::ServiceUnavailable) (5.03).
    pub const SERVICE_UNAVAILABLE: Self = Self(ResponseCode::ServiceUnavailable as u8);
    /// [GatewayTimeout](ResponseCode::GatewayTimeout) (5.04).
    pub const GATEWAY_TIMEOUT: Self = Self(ResponseCode::GatewayTimeout as u8);
    /// [ProxyingNotSupported](ResponseCode::ProxyingNotSupported) (5.05).
    pub const PROXYING_NOT_SUPPORTED: Self = Self(ResponseCode::ProxyingNotSupported as u8);

    /// The upper three bits of the code.
    pub const fn class(self) -> u8 {
        self.0 >> 5
    }

    /// The lower five bits of the code.
    pub const fn detail(self) -> u8 {
        self.0 & 31
    }

    /// Whether this code denotes a request method.
    pub const fn is_request(self) -> bool {
        self.class() == 0 && self.0 != 0
    }

    /// Whether this code belongs to a response class.
    pub const fn is_response(self) -> bool {
        matches!(self.class(), 2 | 4 | 5)
    }

    /// Whether this is the Empty code (0.00).
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl From<u8> for Code {
    fn from(byte: u8) -> Self {
        Self(byte)
    }
}

impl From<Code> for u8 {
    fn from(code: Code) -> Self {
        code.0
    }
}

impl From<RequestCode> for Code {
    fn from(code: RequestCode) -> Self {
        Self(code.into())
    }
}

impl From<ResponseCode> for Code {
    fn from(code: ResponseCode) -> Self {
        Self(code.into())
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.class(), self.detail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Message, MessageBuilder, MessageType};

    #[test]
    fn every_wire_code_round_trips() {
        for byte in u8::MIN..=u8::MAX {
            let code = Code::from(byte);
            let mut buffer = [0; 4];
            let packet = MessageBuilder::new(&mut buffer)
                .unwrap()
                .header(MessageType::Confirmable, code)
                .message_id(42)
                .no_token()
                .unwrap()
                .no_payload()
                .build();
            assert_eq!(packet[1], byte);
            let parsed = Message::parse(packet).unwrap().code;
            assert_eq!(parsed, code);
            assert_eq!(u8::from(parsed), byte);
        }
    }

    #[test]
    fn named_codes_match_the_wire_format() {
        extern crate std;
        assert_eq!(Code::from(RequestCode::Put), Code::PUT);
        assert_eq!(Code::from(ResponseCode::Created), Code::CREATED);
        assert_eq!(std::format!("{}", Code::CREATED), "2.01");
        assert_eq!(std::format!("{}", Code::NOT_FOUND), "4.04");
    }
}
