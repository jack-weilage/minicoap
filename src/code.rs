use crate::coap_code;
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
pub struct Code(pub(crate) u8);

impl Code {
    /// Empty message (0.00).
    pub const EMPTY: Self = Self(0);
    /// The GET method retrieves a representation for the information that currently corresponds to
    /// the resource identified by the request URI. If the request includes an Accept Option, that
    /// indicates the preferred content-format of a response. If the request includes an ETag
    /// Option, the GET method requests that ETag be validated and that the representation be
    /// transferred only if validation failed. Upon success, a 2.05 (Content) or 2.03 (Valid)
    /// Response Code SHOULD be present in the response.
    ///
    /// The GET method is safe and idempotent.
    ///
    /// Source: [RFC 7252 5.8.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.1)
    pub const GET: Self = Self(coap_code!(0, 01));
    /// The POST method requests that the representation enclosed in the request be processed. The
    /// actual function performed by the POST method is determined by the origin server and
    /// dependent on the target resource. It usually results in a new resource being created or the
    /// target resource being updated.
    ///
    /// If a resource has been created on the server, the response returned by the server SHOULD
    /// have a 2.01 (Created) Response Code and SHOULD include the URI of the new resource in a
    /// sequence of one or more Location-Path and/or Location-Query Options (Section 5.10.7). If the
    /// POST succeeds but does not result in a new resource being created on the server, the
    /// response SHOULD have a 2.04 (Changed) Response Code. If the POST succeeds and results in the
    /// target resource being deleted, the response SHOULD have a 2.02 (Deleted) Response Code.
    ///
    /// POST is neither safe nor idempotent.
    ///
    /// Source: [RFC 7252 5.8.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.2)
    pub const POST: Self = Self(coap_code!(0, 02));
    /// The PUT method requests that the resource identified by the request URI be updated or
    /// created with the enclosed representation. The representation format is specified by the
    /// media type and content coding given in the Content-Format Option, if provided.
    ///
    /// If a resource exists at the request URI, the enclosed representation SHOULD be considered a
    /// modified version of that resource, and a 2.04 (Changed) Response Code SHOULD be returned. If
    /// no resource exists, then the server MAY create a new resource with that URI, resulting in a
    /// 2.01 (Created) Response Code. If the resource could not be created or modified, then an
    /// appropriate error Response Code SHOULD be sent.
    ///
    /// Further restrictions to a PUT can be made by including the If-Match (see Section 5.10.8.1)
    /// or If-None-Match (see Section 5.10.8.2) options in the request.
    ///
    /// PUT is not safe but is idempotent.
    ///
    /// Source: [RFC 7252 5.8.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.3)
    pub const PUT: Self = Self(coap_code!(0, 03));
    /// The DELETE method requests that the resource identified by the request URI be deleted.
    /// A 2.02 (Deleted) Response Code SHOULD be used on success or in case the resource did not
    /// exist before the request.
    ///
    /// DELETE is not safe but is idempotent.
    ///
    /// Source: [RFC 7252 5.8.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.4)
    pub const DELETE: Self = Self(coap_code!(0, 04));
    /// The FETCH method is used to obtain a representation of a resource, specified by a number
    /// of request parameters. Unlike GET, which requests the full resource, FETCH allows the client
    /// to ask the server to produce a representation as described by the request parameters
    /// (including request options and payload) based on the resource specified by the request URI.
    ///
    /// The body of the request (which may be constructed from multiple payloads using the block
    /// protocol) together with the request options defines the request parameters. The request body
    /// specifies a media type that describes how to select or filter information from the resource.
    ///
    /// FETCH is both safe and idempotent with regards to the resource identified by the request URI.
    /// That is, the performance of a FETCH is not intended to alter the state of the targeted resource.
    ///
    /// A successful response to a FETCH request is cacheable; the request body is part of the cache key.
    /// Specifically, 2.05 (Content) response codes are a typical way to respond to a FETCH request.
    ///
    /// Source: [RFC 8132 2](https://datatracker.ietf.org/doc/html/rfc8132#section-2)
    pub const FETCH: Self = Self(coap_code!(0, 05));
    /// The PATCH method requests that a set of changes described in the request payload be applied
    /// to the target resource. The set of changes is represented in a format identified by a media
    /// type. If the Request-URI does not point to an existing resource, the server MAY create a new
    /// resource with that URI, depending on the PATCH document type and permissions.
    ///
    /// PATCH is not safe and not idempotent. The difference between PUT and PATCH is that PATCH
    /// allows partial updates: clients cannot use PUT while supplying just the update, but they
    /// might be able to use PATCH.
    ///
    /// PATCH is atomic. The server MUST apply the entire set of changes atomically and never provide
    /// a partially modified representation to a concurrently executed GET request.
    ///
    /// Restrictions to a PATCH request can be made by including the If-Match or If-None-Match
    /// options in the request.
    ///
    /// Source: [RFC 8132 3](https://datatracker.ietf.org/doc/html/rfc8132#section-3)
    pub const PATCH: Self = Self(coap_code!(0, 06));
    /// The iPATCH method is identical to the PATCH method, except that it is idempotent.
    ///
    /// A client can mark a request as idempotent by using the iPATCH method instead of the PATCH
    /// method. This is the only difference between the two. The indication of idempotence may enable
    /// the server to keep less state about the interaction; some constrained servers may only
    /// implement the iPATCH variant for this reason.
    ///
    /// iPATCH is not safe but is idempotent, similar to the CoAP PUT method. Like PATCH, iPATCH
    /// is atomic and the server MUST apply the entire set of changes atomically.
    ///
    /// There is no requirement on the server to check that the client's intention that the request
    /// be idempotent is fulfilled, although there is diagnostic value in that check for less-
    /// constrained implementations.
    ///
    /// Source: [RFC 8132 3](https://datatracker.ietf.org/doc/html/rfc8132#section-3)
    pub const IPATCH: Self = Self(coap_code!(0, 07));
    /// Like HTTP 201 "Created", but only used in response to POST and PUT requests. The payload
    /// returned with the response, if any, is a representation of the action result.
    ///
    /// If the response includes one or more Location-Path and/or Location-Query Options, the values
    /// of these options specify the location at which the resource was created. Otherwise, the
    /// resource was created at the request URI.  A cache receiving this response MUST mark any
    /// stored response for the created resource as not fresh.
    ///
    /// This response is not cacheable.
    ///
    /// Source: [RFC 7252 5.9.1.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.1)
    pub const CREATED: Self = Self(coap_code!(2, 01));
    /// This Response Code is like HTTP 204 "No Content" but only used in response to requests that
    /// cause the resource to cease being available, such as DELETE and, in certain circumstances,
    /// POST. The payload returned with the response, if any, is a representation of the action
    /// result.
    ///
    /// This response is not cacheable. However, a cache MUST mark any stored response for the
    /// deleted resource as not fresh.
    ///
    /// Source: [RFC 7252 5.9.1.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.2)
    pub const DELETED: Self = Self(coap_code!(2, 02));
    /// This Response Code is related to HTTP 304 "Not Modified" but only used to indicate that the
    /// response identified by the entity-tag identified by the included ETag Option is valid.
    /// Accordingly, the response MUST include an ETag Option and MUST NOT include a payload.
    ///
    /// When a cache that recognizes and processes the ETag response option receives a 2.03 (Valid)
    /// response, it MUST update the stored response with the value of the Max-Age Option included
    /// in the response (explicitly, or implicitly as a default value; see also Section 5.6.2). For
    /// each type of Safe-to-Forward option present in the response, the (possibly empty) set of
    /// options of this type that are present in the stored response MUST be replaced with the set
    /// of options of this type in the response received. (Unsafe options may trigger similar
    /// option-specific processing as defined by the option.)
    ///
    /// Source: [RFC 7252 5.9.1.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.3)
    pub const VALID: Self = Self(coap_code!(2, 03));
    /// This Response Code is like HTTP 204 "No Content" but only used in response to POST and PUT
    /// requests. The payload returned with the response, if any, is a representation of the action
    /// result.
    ///
    /// This response is not cacheable. However, a cache MUST mark any stored response for the
    /// changed resource as not fresh.
    ///
    /// Source: [RFC 7252 5.9.1.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.4)
    pub const CHANGED: Self = Self(coap_code!(2, 04));
    /// This Response Code is like HTTP 200 "OK" but only used in response to GET requests.
    ///
    /// The payload returned with the response is a representation of the target resource.
    ///
    /// This response is cacheable: Caches can use the Max-Age Option to determine freshness (see
    /// Section 5.6.1) and (if present) the ETag Option for validation (see Section 5.6.2).
    ///
    /// Source: [RFC 7252 5.9.1.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.5)
    pub const CONTENT: Self = Self(coap_code!(2, 05));
    /// This success status code indicates that the transfer of this block of the request body was
    /// successful and that the server encourages sending further blocks. A final outcome of the
    /// whole block-wise request cannot yet be determined. No payload is returned with this
    /// response code.
    ///
    /// This is used in block-wise transfers when the server has successfully received a block with
    /// the M (more) bit set in the Block1 Option, indicating that the server is ready to receive
    /// more blocks.
    ///
    /// Source: [RFC 7959 2.9.1](https://datatracker.ietf.org/doc/html/rfc7959#section-2.9.1)
    pub const CONTINUE: Self = Self(coap_code!(2, 31));
    /// This Response Code is like HTTP 400 "Bad Request".
    ///
    /// Source: [RFC 7252 5.9.2.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.1)
    pub const BAD_REQUEST: Self = Self(coap_code!(4, 00));
    /// The client is not authorized to perform the requested action.  The client SHOULD NOT repeat
    /// the request without first improving its authentication status to the server. Which specific
    /// mechanism can be used for this is outside this document's scope; see also Section 9.
    ///
    /// Source: [RFC 7252 5.9.2.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.2)
    pub const UNAUTHORIZED: Self = Self(coap_code!(4, 01));
    /// The request could not be understood by the server due to one or more unrecognized or
    /// malformed options. The client SHOULD NOT repeat the request without modification.
    ///
    /// Source: [RFC 7252 5.9.2.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.3)
    pub const BAD_OPTION: Self = Self(coap_code!(4, 02));
    /// This client error status code indicates that the server has not received the blocks of the
    /// request body that it needs to proceed. The client has not sent all blocks, not sent them in
    /// the order required by the server, or has sent them long enough ago that the server has
    /// already discarded them.
    ///
    /// This is used in block-wise transfers to indicate that the server cannot complete the request
    /// because it is missing necessary blocks from a Block1 transfer.
    ///
    /// Source: [RFC 7959 2.9.2](https://datatracker.ietf.org/doc/html/rfc7959#section-2.9.2)
    pub const REQUEST_ENTITY_INCOMPLETE: Self = Self(coap_code!(4, 08));
    /// If the modification specified by a PATCH or iPATCH request causes the resource to enter an
    /// inconsistent state that the server cannot resolve, the server can return the 4.09 (Conflict)
    /// CoAP response. The server SHOULD generate a payload that includes enough information for a
    /// user to recognize the source of the conflict.
    ///
    /// The server MAY return the actual resource state to provide the client with the means to create
    /// a new consistent resource state. Such a situation might be encountered when a structural
    /// modification is applied to a configuration data store but the structures being modified do
    /// not exist.
    ///
    /// Source: [RFC 8132 3.4](https://datatracker.ietf.org/doc/html/rfc8132#section-3.4)
    pub const CONFLICT: Self = Self(coap_code!(4, 09));
    /// This Response Code is like HTTP 403 "Forbidden".
    ///
    /// Source: [RFC 7252 5.9.2.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.4)
    pub const FORBIDDEN: Self = Self(coap_code!(4, 03));
    /// This Response Code is like HTTP 404 "Not Found".
    ///
    /// Source: [RFC 7252 5.9.2.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.5)
    pub const NOT_FOUND: Self = Self(coap_code!(4, 04));
    /// This Response Code is like HTTP 405 "Method Not Allowed" but with no parallel to the
    /// "Allow" header field.
    ///
    /// Source: [RFC 7252 5.9.2.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.6)
    pub const METHOD_NOT_ALLOWED: Self = Self(coap_code!(4, 05));
    /// This Response Code is like HTTP 406 "Not Acceptable", but with no response entity.
    ///
    /// Source: [RFC 7252 5.9.2.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.7)
    pub const NOT_ACCEPTABLE: Self = Self(coap_code!(4, 06));
    /// This Response Code is like HTTP 412 "Precondition Failed".
    ///
    /// Source: [RFC 7252 5.9.2.8](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.8)
    pub const PRECONDITION_FAILED: Self = Self(coap_code!(4, 12));
    /// This Response Code is like HTTP 413 "Request Entity Too Large".
    ///
    /// The response SHOULD include a Size1 Option to indicate the maximum size of request entity
    /// the server is able and willing to handle, unless the server is not in a position to make
    /// this information available.
    ///
    /// In the context of block-wise transfers (RFC 7959), this response can be returned at any
    /// time during a Block1 transfer to indicate that the server does not currently have the
    /// resources to store blocks for a transfer that it would intend to implement atomically. It
    /// can also be used as a hint for the client to try sending Block1, or with a smaller SZX in
    /// its Block1 Option than requested as a hint to try a smaller block size.
    ///
    /// Source: [RFC 7252 5.9.2.9](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.9),
    /// [RFC 7959 2.9.3](https://datatracker.ietf.org/doc/html/rfc7959#section-2.9.3)
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self(coap_code!(4, 13));
    /// This Response Code is like HTTP 415 "Unsupported Media Type".
    ///
    /// Source: [RFC 7252 5.9.2.10](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.10)
    pub const UNSUPPORTED_CONTENT_FORMAT: Self = Self(coap_code!(4, 15));
    /// This situation occurs when the payload of a PATCH or FETCH request is determined to be valid
    /// (i.e., well-formed and supported) but the server is unable to or is incapable of processing
    /// the request.
    ///
    /// For PATCH/iPATCH, this might include situations such as:
    /// - The server has insufficient computing resources to complete the request successfully
    ///   (though 4.13 Request Entity Too Large may be more appropriate)
    /// - The resource specified in the request becomes invalid by applying the payload
    ///   (though 4.09 Conflict may be more appropriate for this case)
    ///
    /// For FETCH, this can be returned when the server is unable to process a well-formed and
    /// supported request payload.
    ///
    /// In case there are more specific errors that provide additional insight into the problem,
    /// those should be used instead.
    ///
    /// Source: [RFC 8132 2.2](https://datatracker.ietf.org/doc/html/rfc8132#section-2.2),
    /// [RFC 8132 3.4](https://datatracker.ietf.org/doc/html/rfc8132#section-3.4)
    pub const UNPROCESSABLE_ENTITY: Self = Self(coap_code!(4, 22));
    /// This Response Code is like HTTP 500 "Internal Server Error".
    ///
    /// Source: [RFC 7252 5.9.3.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.1)
    pub const INTERNAL_SERVER_ERROR: Self = Self(coap_code!(5, 00));
    /// This Response Code is like HTTP 501 "Not Implemented".
    ///
    /// Source: [RFC 7252 5.9.3.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.2)
    pub const NOT_IMPLEMENTED: Self = Self(coap_code!(5, 01));
    /// This Response Code is like HTTP 502 "Bad Gateway".
    ///
    /// Source: [RFC 7252 5.9.3.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.3)
    pub const BAD_GATEWAY: Self = Self(coap_code!(5, 02));
    /// This Response Code is like HTTP 503 "Service Unavailable" but uses the Max-Age Option in
    /// place of the "Retry-After" header field to indicate the number of seconds after which to retry.
    ///
    /// Source: [RFC 7252 5.9.3.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.4)
    pub const SERVICE_UNAVAILABLE: Self = Self(coap_code!(5, 03));
    /// This Response Code is like HTTP 504 "Gateway Timeout".
    ///
    /// Source: [RFC 7252 5.9.3.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.5)
    pub const GATEWAY_TIMEOUT: Self = Self(coap_code!(5, 04));
    /// The server is unable or unwilling to act as a forward-proxy for the URI specified in the
    /// Proxy-Uri Option or using Proxy-Scheme (see Section 5.10.2).
    ///
    /// Source: [RFC 7252 5.9.3.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.6)
    pub const PROXYING_NOT_SUPPORTED: Self = Self(coap_code!(5, 05));

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
        assert_eq!(u8::from(Code::PUT), 3);
        assert_eq!(u8::from(Code::CREATED), 65);
        assert_eq!(std::format!("{}", Code::CREATED), "2.01");
        assert_eq!(std::format!("{}", Code::NOT_FOUND), "4.04");
    }
}
