//! # `minicoap`
//!
//! A minimal, zero-copy CoAP message parser and builder for embedded systems.
//!
//! ## Supported RFCs
//!
//! - [RFC 7252](https://datatracker.ietf.org/doc/html/rfc7252): The Constrained Application Protocol (CoAP)
//! - [RFC 7959](https://datatracker.ietf.org/doc/html/rfc7959): Block-Wise Transfers in CoAP
//! - [RFC 8132](https://datatracker.ietf.org/doc/html/rfc8132): PATCH and FETCH Methods for CoAP
//! - [RFC 9175](https://datatracker.ietf.org/doc/html/rfc9175): CoAP: Echo, Request-Tag, and Token Processing

#![no_std]
#![deny(clippy::cargo, missing_docs)]
#![warn(clippy::all)]

use num_enum::{FromPrimitive, IntoPrimitive};

mod builder;
pub(crate) mod error;
mod parser;

pub use builder::MessageBuilder;
#[doc(hidden)]
pub use builder::{Complete, NeedsBuffer, NeedsHeader, NeedsMessageId, NeedsPayload, NeedsToken};
pub use error::{CoapBuildError, CoapParseError};
pub use parser::{CoapOption, CoapOptions, Message, OptionIterator};

#[macro_export]
/// Converts a CoAP code into a u8 value.
macro_rules! coap_code {
    ($class:expr, $detail:expr) => {{
        const CLASS: u8 = $class;
        const DETAIL: u8 = $detail;

        const {
            assert!(CLASS <= 0b111, "CoAP class must be between 0 and 7");
            assert!(DETAIL <= 0b11111, "CoAP detail must be between 0 and 31");
        };

        (CLASS << 5) | DETAIL
    }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// CoAP specification version
pub enum Version {
    /// Version 1 ([RFC 7252](https://datatracker.ietf.org/doc/html/rfc7252))
    V1 = 0b01,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// CoAP message type
pub enum MessageType {
    /// Some messages require an acknowledgement. These messages are called "Confirmable". When no
    /// packets are lost, each Confirmable message elicits exactly one return message of type
    /// [`Acknowledgement`](MessageType::Acknowledgement) or type [`Reset`](MessageType::Reset).
    ///
    /// Source: [RFC 7252 1.2](https://datatracker.ietf.org/doc/html/rfc7252#section-1.2)
    Confirmable = 0,
    /// Some other messages do not require an acknowledgement. This is particularly true for
    /// messages that are repeated regularly for application requirements, such as repeated readings
    /// from a sensor.
    ///
    /// Source: [RFC 7252 1.2](https://datatracker.ietf.org/doc/html/rfc7252#section-1.2)
    NonConfirmable = 1,
    /// An Acknowledgement message acknowledges that a specific Confirmable message arrived. By
    /// itself, an Acknowledgement message does not indicate success or failure of any request
    /// encapsulated in the Confirmable message, but the Acknowledgement message may also carry a
    /// Piggybacked Response.
    ///
    /// Source: [RFC 7252 1.2](https://datatracker.ietf.org/doc/html/rfc7252#section-1.2)
    Acknowledgement = 2,
    /// A Reset message indicates that a specific message (Confirmable or Non-confirmable) was
    /// received, but some context is missing to properly process it. This condition is usually
    /// caused when the receiving node has rebooted and has forgotten some state that would be
    /// required to interpret the message. Provoking a Reset message (e.g., by sending an Empty
    /// Confirmable message) is also useful as an inexpensive check of the liveness of an endpoint
    /// ("CoAP ping").
    ///
    /// Source: [RFC 7252 1.2](https://datatracker.ietf.org/doc/html/rfc7252#section-1.2)
    Reset = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// Request codes for CoAP messages
pub enum RequestCode {
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
    Get = coap_code!(0, 01),
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
    Post = coap_code!(0, 02),
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
    Put = coap_code!(0, 03),
    /// The DELETE method requests that the resource identified by the request URI be deleted.
    /// A 2.02 (Deleted) Response Code SHOULD be used on success or in case the resource did not
    /// exist before the request.
    ///
    /// DELETE is not safe but is idempotent.
    ///
    /// Source: [RFC 7252 5.8.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.4)
    Delete = coap_code!(0, 04),
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
    Fetch = coap_code!(0, 05),
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
    Patch = coap_code!(0, 06),
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
    IPatch = coap_code!(0, 07),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// Response codes for CoAP packets
pub enum ResponseCode {
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
    Created = coap_code!(2, 01),
    /// This Response Code is like HTTP 204 "No Content" but only used in response to requests that
    /// cause the resource to cease being available, such as DELETE and, in certain circumstances,
    /// POST. The payload returned with the response, if any, is a representation of the action
    /// result.
    ///
    /// This response is not cacheable. However, a cache MUST mark any stored response for the
    /// deleted resource as not fresh.
    ///
    /// Source: [RFC 7252 5.9.1.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.2)
    Deleted = coap_code!(2, 02),

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
    Valid = coap_code!(2, 03),
    /// This Response Code is like HTTP 204 "No Content" but only used in response to POST and PUT
    /// requests. The payload returned with the response, if any, is a representation of the action
    /// result.
    ///
    /// This response is not cacheable. However, a cache MUST mark any stored response for the
    /// changed resource as not fresh.
    ///
    /// Source: [RFC 7252 5.9.1.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.4)
    Changed = coap_code!(2, 04),
    /// This Response Code is like HTTP 200 "OK" but only used in response to GET requests.
    ///
    /// The payload returned with the response is a representation of the target resource.
    ///
    /// This response is cacheable: Caches can use the Max-Age Option to determine freshness (see
    /// Section 5.6.1) and (if present) the ETag Option for validation (see Section 5.6.2).
    ///
    /// Source: [RFC 7252 5.9.1.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.1.5)
    Content = coap_code!(2, 05),
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
    Continue = coap_code!(2, 31),

    /// This Response Code is like HTTP 400 "Bad Request".
    ///
    /// Source: [RFC 7252 5.9.2.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.1)
    BadRequest = coap_code!(4, 00),
    /// The client is not authorized to perform the requested action.  The client SHOULD NOT repeat
    /// the request without first improving its authentication status to the server. Which specific
    /// mechanism can be used for this is outside this document's scope; see also Section 9.
    ///
    /// Source: [RFC 7252 5.9.2.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.2)
    Unauthorized = coap_code!(4, 01),
    /// The request could not be understood by the server due to one or more unrecognized or
    /// malformed options. The client SHOULD NOT repeat the request without modification.
    ///
    /// Source: [RFC 7252 5.9.2.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.3)
    BadOption = coap_code!(4, 02),
    /// This client error status code indicates that the server has not received the blocks of the
    /// request body that it needs to proceed. The client has not sent all blocks, not sent them in
    /// the order required by the server, or has sent them long enough ago that the server has
    /// already discarded them.
    ///
    /// This is used in block-wise transfers to indicate that the server cannot complete the request
    /// because it is missing necessary blocks from a Block1 transfer.
    ///
    /// Source: [RFC 7959 2.9.2](https://datatracker.ietf.org/doc/html/rfc7959#section-2.9.2)
    RequestEntityIncomplete = coap_code!(4, 08),
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
    Conflict = coap_code!(4, 09),
    /// This Response Code is like HTTP 403 "Forbidden".
    ///
    /// Source: [RFC 7252 5.9.2.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.4)
    Forbidden = coap_code!(4, 03),
    /// This Response Code is like HTTP 404 "Not Found".
    ///
    /// Source: [RFC 7252 5.9.2.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.5)
    NotFound = coap_code!(4, 04),
    /// This Response Code is like HTTP 405 "Method Not Allowed" but with no parallel to the
    /// "Allow" header field.
    ///
    /// Source: [RFC 7252 5.9.2.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.6)
    MethodNotAllowed = coap_code!(4, 05),
    /// This Response Code is like HTTP 406 "Not Acceptable", but with no response entity.
    ///
    /// Source: [RFC 7252 5.9.2.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.7)
    NotAcceptable = coap_code!(4, 06),
    /// This Response Code is like HTTP 412 "Precondition Failed".
    ///
    /// Source: [RFC 7252 5.9.2.8](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.8)
    PreconditionFailed = coap_code!(4, 12),
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
    RequestEntityTooLarge = coap_code!(4, 13),
    /// This Response Code is like HTTP 415 "Unsupported Media Type".
    ///
    /// Source: [RFC 7252 5.9.2.10](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.2.10)
    UnsupportedContentFormat = coap_code!(4, 15),
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
    UnprocessableEntity = coap_code!(4, 22),

    /// This Response Code is like HTTP 500 "Internal Server Error".
    ///
    /// Source: [RFC 7252 5.9.3.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.1)
    InternalServerError = coap_code!(5, 00),
    /// This Response Code is like HTTP 501 "Not Implemented".
    ///
    /// Source: [RFC 7252 5.9.3.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.2)
    NotImplemented = coap_code!(5, 01),
    /// This Response Code is like HTTP 502 "Bad Gateway".
    ///
    /// Source: [RFC 7252 5.9.3.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.3)
    BadGateway = coap_code!(5, 02),
    /// This Response Code is like HTTP 503 "Service Unavailable" but uses the Max-Age Option in
    /// place of the "Retry-After" header field to indicate the number of seconds after which to retry.
    ///
    /// Source: [RFC 7252 5.9.3.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.4)
    ServiceUnavailable = coap_code!(5, 03),
    /// This Response Code is like HTTP 504 "Gateway Timeout".
    ///
    /// Source: [RFC 7252 5.9.3.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.5)
    GatewayTimeout = coap_code!(5, 04),
    /// The server is unable or unwilling to act as a forward-proxy for the URI specified in the
    /// Proxy-Uri Option or using Proxy-Scheme (see Section 5.10.2).
    ///
    /// Source: [RFC 7252 5.9.3.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.9.3.6)
    ProxyingNotSupported = coap_code!(5, 05),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, FromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
/// CoAP option numbers as defined in RFC 7252.
///
/// Options are used in CoAP messages to express additional information. Each option instance in a
/// message specifies the Option Number of the defined CoAP option, the length of the Option Value,
/// and the Option Value itself.
///
/// Source: [RFC 7252 5.10](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10)
pub enum OptionNumber {
    /// The If-Match Option MAY be used to make a request conditional on the current existence or
    /// value of an ETag for one or more representations of the target resource. If-Match is
    /// generally useful for resource update requests, such as PUT requests, as a means for
    /// protecting against accidental overwrites when multiple clients are acting in parallel on
    /// the same resource (i.e., the "lost update" problem).
    ///
    /// The value of an If-Match option is either an ETag or the empty string. An If-Match option
    /// with an ETag matches a representation with that exact ETag. An If-Match option with an
    /// empty value matches any existing representation (i.e., it places the precondition on the
    /// existence of any current representation for the target resource).
    ///
    /// The If-Match Option can occur multiple times. If any of the options match, then the
    /// condition is fulfilled.
    ///
    /// If there is one or more If-Match Options, but none of the options match, then the condition
    /// is not fulfilled.
    ///
    /// Source: [RFC 7252 5.10.8.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.1)
    IfMatch = 1,
    /// The Uri-Host Option specifies the Internet host of the resource being requested.
    ///
    /// The default value of the Uri-Host Option is the IP literal representing the destination IP
    /// address of the request message. The default value for the Uri-Host Option is sufficient
    /// for requests to most servers. Explicit Uri-Host Options are typically used when an
    /// endpoint hosts multiple virtual servers.
    ///
    /// The Uri-Path Option can contain any character sequence. No percent-encoding is performed.
    /// The value of a Uri-Path Option MUST NOT be "." or ".." (as the request URI must be resolved
    /// before parsing it into options).
    ///
    /// Source: [RFC 7252 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)
    UriHost = 3,
    /// The ETag Option in a response provides the current value (i.e., after the request was
    /// processed) of the entity-tag for the "tagged representation". If no Location-* options are
    /// present, the tagged representation is the selected representation of the target resource. If
    /// one or more Location-* options are present and thus a location URI is indicated, the tagged
    /// representation is the representation that would be retrieved by a GET request to the location
    /// URI.
    ///
    /// An ETag response option can be included with any response for which there is a tagged
    /// representation. The ETag Option MUST NOT occur more than once in a response.
    ///
    /// In a GET request, an endpoint that has one or more representations previously obtained from
    /// the resource, and has obtained ETag response options with these, can specify an instance of
    /// the ETag Option for one or more of these stored responses. A server can issue a 2.03 Valid
    /// response in place of a 2.05 Content response if one of the ETags given is the entity-tag for
    /// the current representation. The ETag Option MAY occur zero, one, or multiple times in a
    /// request.
    ///
    /// Source: [RFC 7252 5.10.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.6)
    Etag = 4,
    /// The If-None-Match Option MAY be used to make a request conditional on the nonexistence of
    /// the target resource. If-None-Match is useful for resource creation requests, such as PUT
    /// requests, as a means for protecting against accidental overwrites when multiple clients are
    /// acting in parallel on the same resource. The If-None-Match Option carries no value.
    ///
    /// If the target resource does exist, then the condition is not fulfilled.
    ///
    /// (It is not very useful to combine If-Match and If-None-Match options in one request,
    /// because the condition will then never be fulfilled.)
    ///
    /// Source: [RFC 7252 5.10.8.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.2)
    IfNoneMatch = 5,
    /// The Uri-Port Option specifies the transport-layer port number of the resource.
    ///
    /// The default value of the Uri-Port Option is the destination UDP port. The default value for
    /// the Uri-Port Option is sufficient for requests to most servers. Explicit Uri-Port Options
    /// are typically used when an endpoint hosts multiple virtual servers.
    ///
    /// Source: [RFC 7252 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)
    UriPort = 7,
    /// The Location-Path and Location-Query Options together indicate a relative URI that consists
    /// either of an absolute path, a query string, or both. A combination of these options is
    /// included in a 2.01 (Created) response to indicate the location of the resource created as the
    /// result of a POST request.
    ///
    /// Each Location-Path Option specifies one segment of the absolute path to the resource. The
    /// Location-Path Option can contain any character sequence. No percent-encoding is performed.
    /// The value of a Location-Path Option MUST NOT be "." or "..".
    ///
    /// If a response with one or more Location-Path and/or Location-Query Options passes through a
    /// cache that interprets these options and the implied URI identifies one or more currently
    /// stored responses, those entries MUST be marked as not fresh.
    ///
    /// Source: [RFC 7252 5.10.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.7)
    LocationPath = 8,
    /// The Uri-Host, Uri-Port, Uri-Path, and Uri-Query Options are used to specify the target
    /// resource of a request to a CoAP origin server. Each Uri-Path Option specifies one segment of
    /// the absolute path to the resource.
    ///
    /// The Uri-Path Option can contain any character sequence. No percent-encoding is performed. The
    /// value of a Uri-Path Option MUST NOT be "." or ".." (as the request URI must be resolved
    /// before parsing it into options).
    ///
    /// Source: [RFC 7252 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)
    UriPath = 11,
    /// The Content-Format Option indicates the representation format of the message payload. The
    /// representation format is given as a numeric Content-Format identifier that is defined in the
    /// "CoAP Content-Formats" registry. In the absence of the option, no default value is assumed,
    /// i.e., the representation format of any representation message payload is indeterminate.
    ///
    /// Source: [RFC 7252 5.10.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.3)
    ContentFormat = 12,
    /// The Max-Age Option indicates the maximum time a response may be cached before it is
    /// considered not fresh (see Section 5.6.1).
    ///
    /// The option value is an integer number of seconds between 0 and 2**32-1 inclusive (about
    /// 136.1 years). A default value of 60 seconds is assumed in the absence of the option in a
    /// response.
    ///
    /// The value is intended to be current at the time of transmission. Servers that provide
    /// resources with strict tolerances on the value of Max-Age SHOULD update the value before
    /// each retransmission. (See also Section 5.7.1.)
    ///
    /// Source: [RFC 7252 5.10.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.5)
    MaxAge = 14,
    /// The Uri-Host, Uri-Port, Uri-Path, and Uri-Query Options are used to specify the target
    /// resource of a request to a CoAP origin server. Each Uri-Query Option specifies one argument
    /// parameterizing the resource.
    ///
    /// The Uri-Query Option can contain any character sequence. No percent-encoding is performed.
    ///
    /// Source: [RFC 7252 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)
    UriQuery = 15,
    /// The CoAP Accept option can be used to indicate which Content-Format is acceptable to the
    /// client. The representation format is given as a numeric Content-Format identifier that is
    /// defined in the "CoAP Content-Formats" registry (Section 12.3). If no Accept option is given,
    /// the client does not express a preference (thus no default value is assumed). The client
    /// prefers the representation returned by the server to be in the Content-Format indicated.
    /// The server returns the preferred Content-Format if available. If the preferred Content-
    /// Format cannot be returned, then a 4.06 "Not Acceptable" MUST be sent as a response, unless
    /// another error code takes precedence for this response.
    ///
    /// Source: [RFC 7252 5.10.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.4)
    Accept = 17,
    /// The Location-Path and Location-Query Options together indicate a relative URI that consists
    /// either of an absolute path, a query string, or both. A combination of these options is
    /// included in a 2.01 (Created) response to indicate the location of the resource created as the
    /// result of a POST request.
    ///
    /// Each Location-Query Option specifies one argument parameterizing the resource. The
    /// Location-Query Option can contain any character sequence. No percent-encoding is performed.
    ///
    /// If a response with one or more Location-Path and/or Location-Query Options passes through a
    /// cache that interprets these options and the implied URI identifies one or more currently
    /// stored responses, those entries MUST be marked as not fresh.
    ///
    /// Source: [RFC 7252 5.10.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.7)
    LocationQuery = 20,
    /// The Block2 Option provides block-wise transfer of response payloads. It indicates a
    /// block-wise transfer and describes how this specific block-wise payload forms part of the
    /// entire body being transferred. The option value is a variable-size (0 to 3 byte) unsigned
    /// integer encoding the block number (NUM), more flag (M), and size exponent (SZX).
    ///
    /// This is a Critical option.
    ///
    /// Source: [RFC 7959 2.1](https://datatracker.ietf.org/doc/html/rfc7959#section-2.1)
    Block2 = 23,
    /// The Block1 Option provides block-wise transfer of request payloads. It indicates a
    /// block-wise transfer and describes how this specific block-wise payload forms part of the
    /// entire body being transferred. The option value is a variable-size (0 to 3 byte) unsigned
    /// integer encoding the block number (NUM), more flag (M), and size exponent (SZX).
    ///
    /// This is a Critical option.
    ///
    /// Source: [RFC 7959 2.1](https://datatracker.ietf.org/doc/html/rfc7959#section-2.1)
    Block1 = 27,
    /// The Size2 Option indicates the size of the resource representation transferred in
    /// responses. In a request with value 0, it asks the server to provide a size estimate. In a
    /// response carrying a Block2 Option, it indicates the current estimate the server has of the
    /// total size of the resource representation, measured in bytes.
    ///
    /// This is an Elective option.
    ///
    /// Source: [RFC 7959 4](https://datatracker.ietf.org/doc/html/rfc7959#section-4)
    Size2 = 28,
    /// The Proxy-Uri Option is used to make a request to a forward-proxy. The forward-proxy is
    /// requested to forward the request or service it from a valid cache and return the response.
    ///
    /// The option value is an absolute-URI. Note that the forward-proxy MAY forward the request on
    /// to another proxy or directly to the server specified by the absolute-URI. In order to avoid
    /// request loops, a proxy MUST be able to recognize all of its server names, including any
    /// aliases, local variations, and the numeric IP addresses.
    ///
    /// An endpoint receiving a request with a Proxy-Uri Option that is unable or unwilling to act as
    /// a forward-proxy for the request MUST cause the return of a 5.05 (Proxying Not Supported)
    /// response.
    ///
    /// The Proxy-Uri Option MUST take precedence over any of the Uri-Host, Uri-Port, Uri-Path or
    /// Uri-Query options (each of which MUST NOT be included in a request containing the Proxy-Uri
    /// Option).
    ///
    /// Source: [RFC 7252 5.10.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.2)
    ProxyUri = 35,
    /// As a special case to simplify many proxy clients, the absolute-URI can be constructed from
    /// the Uri-* options. When a Proxy-Scheme Option is present, the absolute-URI is constructed as
    /// follows: a CoAP URI is constructed from the Uri-* options as defined in Section 6.5. In the
    /// resulting URI, the initial scheme up to, but not including, the following colon is then
    /// replaced by the content of the Proxy-Scheme Option.
    ///
    /// Note that this case is only applicable if the components of the desired URI other than the
    /// scheme component actually can be expressed using Uri-* options; for example, to represent a
    /// URI with a userinfo component in the authority, only Proxy-Uri can be used.
    ///
    /// Source: [RFC 7252 5.10.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.2)
    ProxyScheme = 39,
    /// The Size1 Option indicates the size of the resource representation in a request. In a
    /// request carrying a Block1 Option, it indicates the current estimate the client has of the
    /// total size of the resource representation, measured in bytes. In a 4.13 response, it
    /// indicates the maximum size of request entity that the server is able and willing to handle.
    ///
    /// This is an Elective option.
    ///
    /// Source: [RFC 7252 5.10.9](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.9),
    /// [RFC 7959 4](https://datatracker.ietf.org/doc/html/rfc7959#section-4)
    Size1 = 60,
    /// The Echo Option enables a CoAP server to verify the freshness of a request or to force a
    /// client to demonstrate reachability at its claimed network address. The Echo option value is
    /// a challenge from the server to the client, included in a response and echoed back to the
    /// server in subsequent requests.
    ///
    /// The option value is opaque and should be treated as such by clients. Typical length is
    /// 1-40 bytes. This is an elective option that is safe to forward and not part of the cache key.
    ///
    /// Source: [RFC 9175 2.2](https://datatracker.ietf.org/doc/html/rfc9175#section-2.2)
    Echo = 252,
    /// The Request-Tag Option allows a CoAP server to match block-wise message fragments belonging
    /// to the same request. It provides a short-lived identifier set by the client to distinguish
    /// concurrent block-wise request operations on a single resource.
    ///
    /// The option value is opaque with a length of 0-8 bytes. This is an elective option that is
    /// safe to forward, part of the cache key, and repeatable.
    ///
    /// Source: [RFC 9175 3.2](https://datatracker.ietf.org/doc/html/rfc9175#section-3.2)
    RequestTag = 292,

    /// An unrecognized option number. This is used as a catch-all for option numbers that are not
    /// explicitly defined in this implementation. CoAP endpoints can ignore elective options they
    /// don't understand, but critical options (where the option number is odd) must be understood
    /// or the message must be rejected with a 4.02 (Bad Option) response.
    #[num_enum(catch_all)]
    UnknownOption(u16),
}
impl OptionNumber {
    /// Checks if the option number is critical.
    pub fn is_critical(&self) -> bool {
        u16::from(*self) & 1 == 1
    }

    /// Checks if the option number is unsafe.
    pub fn is_unsafe(&self) -> bool {
        u16::from(*self) & 2 == 2
    }

    /// Checks if the option number is no-cache-key.
    pub fn is_no_cache_key(&self) -> bool {
        u16::from(*self) & 0x1e == 0x1c
    }
}

/// CoAP Content-Format identifiers as defined in the CoAP Content-Formats registry.
///
/// The Content-Format Option indicates the representation format of the message payload.
/// The representation format is given as a numeric Content-Format identifier.
///
/// Source: [RFC 7252 5.10.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.3),
/// [RFC 7252 12.3](https://datatracker.ietf.org/doc/html/rfc7252#section-12.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, FromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum ContentFormat {
    /// text/plain; charset=utf-8
    TextPlain = 0,
    /// application/link-format
    ApplicationLinkFormat = 40,
    /// application/xml
    ApplicationXml = 41,
    /// application/octet-stream
    ApplicationOctetStream = 42,
    /// application/exi
    ApplicationExi = 47,
    /// application/json
    ApplicationJson = 50,
    /// application/json-patch+json
    ///
    /// This media type is used to describe a JSON document structure for expressing a sequence of
    /// operations to apply to a JSON document. It is suitable for use with the HTTP PATCH method
    /// and the CoAP PATCH and iPATCH methods.
    ///
    /// Source: [RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902),
    /// [RFC 8132 6](https://datatracker.ietf.org/doc/html/rfc8132#section-6)
    ApplicationJsonPatch = 51,
    /// application/merge-patch+json
    ///
    /// This media type is used to describe a JSON document structure for expressing a set of changes
    /// to be applied to a target JSON document using the JSON Merge Patch algorithm. It is suitable
    /// for use with the HTTP PATCH method and the CoAP PATCH and iPATCH methods.
    ///
    /// JSON Merge Patch is less expressive than JSON Patch but is simpler to use for basic updates.
    ///
    /// Source: [RFC 7396](https://datatracker.ietf.org/doc/html/rfc7396),
    /// [RFC 8132 6](https://datatracker.ietf.org/doc/html/rfc8132#section-6)
    ApplicationMergePatch = 52,

    /// An unrecognized content format. CoAP allows for content formats beyond those
    /// defined in the base specification.
    #[num_enum(catch_all)]
    Unknown(u16),
}
