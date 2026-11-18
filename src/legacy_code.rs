use crate::Code;
use num_enum::IntoPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// Request codes for CoAP messages
#[deprecated(since = "0.4.0", note = "use `Code` constants such as `Code::GET`")]
pub enum RequestCode {
    /// See [`Code::GET`].
    Get = Code::GET.0,
    /// See [`Code::POST`].
    Post = Code::POST.0,
    /// See [`Code::PUT`].
    Put = Code::PUT.0,
    /// See [`Code::DELETE`].
    Delete = Code::DELETE.0,
    /// See [`Code::FETCH`].
    Fetch = Code::FETCH.0,
    /// See [`Code::PATCH`].
    Patch = Code::PATCH.0,
    /// See [`Code::IPATCH`].
    IPatch = Code::IPATCH.0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// Response codes for CoAP packets
#[deprecated(since = "0.4.0", note = "use `Code` constants such as `Code::CONTENT`")]
pub enum ResponseCode {
    /// See [`Code::CREATED`].
    Created = Code::CREATED.0,
    /// See [`Code::DELETED`].
    Deleted = Code::DELETED.0,

    /// See [`Code::VALID`].
    Valid = Code::VALID.0,
    /// See [`Code::CHANGED`].
    Changed = Code::CHANGED.0,
    /// See [`Code::CONTENT`].
    Content = Code::CONTENT.0,
    /// See [`Code::CONTINUE`].
    Continue = Code::CONTINUE.0,

    /// See [`Code::BAD_REQUEST`].
    BadRequest = Code::BAD_REQUEST.0,
    /// See [`Code::UNAUTHORIZED`].
    Unauthorized = Code::UNAUTHORIZED.0,
    /// See [`Code::BAD_OPTION`].
    BadOption = Code::BAD_OPTION.0,
    /// See [`Code::REQUEST_ENTITY_INCOMPLETE`].
    RequestEntityIncomplete = Code::REQUEST_ENTITY_INCOMPLETE.0,
    /// See [`Code::CONFLICT`].
    Conflict = Code::CONFLICT.0,
    /// See [`Code::FORBIDDEN`].
    Forbidden = Code::FORBIDDEN.0,
    /// See [`Code::NOT_FOUND`].
    NotFound = Code::NOT_FOUND.0,
    /// See [`Code::METHOD_NOT_ALLOWED`].
    MethodNotAllowed = Code::METHOD_NOT_ALLOWED.0,
    /// See [`Code::NOT_ACCEPTABLE`].
    NotAcceptable = Code::NOT_ACCEPTABLE.0,
    /// See [`Code::PRECONDITION_FAILED`].
    PreconditionFailed = Code::PRECONDITION_FAILED.0,
    /// See [`Code::REQUEST_ENTITY_TOO_LARGE`].
    RequestEntityTooLarge = Code::REQUEST_ENTITY_TOO_LARGE.0,
    /// See [`Code::UNSUPPORTED_CONTENT_FORMAT`].
    UnsupportedContentFormat = Code::UNSUPPORTED_CONTENT_FORMAT.0,
    /// See [`Code::UNPROCESSABLE_ENTITY`].
    UnprocessableEntity = Code::UNPROCESSABLE_ENTITY.0,

    /// See [`Code::INTERNAL_SERVER_ERROR`].
    InternalServerError = Code::INTERNAL_SERVER_ERROR.0,
    /// See [`Code::NOT_IMPLEMENTED`].
    NotImplemented = Code::NOT_IMPLEMENTED.0,
    /// See [`Code::BAD_GATEWAY`].
    BadGateway = Code::BAD_GATEWAY.0,
    /// See [`Code::SERVICE_UNAVAILABLE`].
    ServiceUnavailable = Code::SERVICE_UNAVAILABLE.0,
    /// See [`Code::GATEWAY_TIMEOUT`].
    GatewayTimeout = Code::GATEWAY_TIMEOUT.0,
    /// See [`Code::PROXYING_NOT_SUPPORTED`].
    ProxyingNotSupported = Code::PROXYING_NOT_SUPPORTED.0,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Message, MessageBuilder, MessageType};

    #[test]
    fn legacy_builders_preserve_codes() {
        let mut buf = [0; 4];
        let packet = MessageBuilder::new(&mut buf)
            .unwrap()
            .request(MessageType::Confirmable, RequestCode::Get)
            .message_id(1)
            .no_token()
            .unwrap()
            .no_payload()
            .build();
        assert_eq!(Message::parse(packet).unwrap().code, Code::GET);
        let packet = MessageBuilder::new(&mut buf)
            .unwrap()
            .response(MessageType::Acknowledgement, ResponseCode::Content)
            .message_id(1)
            .no_token()
            .unwrap()
            .no_payload()
            .build();
        assert_eq!(Message::parse(packet).unwrap().code, Code::CONTENT);
    }
}
