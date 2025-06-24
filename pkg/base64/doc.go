// Package base64 provides base64url encoding and decoding functions
// as defined in RFC 4648 Section 5, specifically for use in JSON Web
// Signatures (JWS) and JSON Web Tokens (JWT) as specified in RFC 7515.
//
// The key difference from standard base64 encoding is:
//   - Uses URL-safe characters (- and _ instead of + and /)
//   - Omits padding characters (=) in the encoded output
//   - Automatically handles padding when decoding
//
// This implementation is designed for cryptographic applications where
// base64url encoding is required for web-safe transmission of binary data.
//
// http://www.rfc-editor.org/rfc/rfc4648#section-5
package base64
