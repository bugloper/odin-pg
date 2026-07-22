package pg

// Legacy password authentication helpers. SCRAM-SHA-256 (auth_scram.odin)
// is the primary mechanism; md5 is deprecated upstream (PostgreSQL 18 warns
// on password_encryption=md5) and cleartext is refused unless the transport
// is TLS or the config opts in.

import "core:crypto/legacy/md5"

// md5_auth_response computes the PasswordMessage payload for
// AuthenticationMD5Password: "md5" + hex(md5(hex(md5(password + user)) + salt)).
// The result is written into out (which must hold MD5_RESPONSE_LEN bytes)
// and returned as a string view over it — no allocation, nothing secret
// left behind to scrub.
MD5_RESPONSE_LEN :: 3 + 32

md5_auth_response :: proc(
	out: ^[MD5_RESPONSE_LEN]u8,
	user, password: string,
	salt: []byte,
) -> string {
	digest: [md5.DIGEST_SIZE]u8
	inner_hex: [32]u8

	ctx: md5.Context
	md5.init(&ctx)
	md5.update(&ctx, transmute([]byte)password)
	md5.update(&ctx, transmute([]byte)user)
	md5.final(&ctx, digest[:])
	hex_encode_lower(inner_hex[:], digest[:])

	md5.init(&ctx)
	md5.update(&ctx, inner_hex[:])
	md5.update(&ctx, salt)
	md5.final(&ctx, digest[:])

	out[0] = 'm'
	out[1] = 'd'
	out[2] = '5'
	hex_encode_lower(out[3:], digest[:])
	return string(out[:])
}

// hex_encode_lower writes lowercase hex without allocating (core:encoding/hex
// only offers allocating encoders).
@(private)
hex_encode_lower :: proc(dst, src: []byte) {
	table := "0123456789abcdef"
	assert(len(dst) >= len(src) * 2)
	for b, i in src {
		dst[i * 2] = table[b >> 4]
		dst[i * 2 + 1] = table[b & 0xF]
	}
}
