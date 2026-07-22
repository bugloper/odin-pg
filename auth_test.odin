package pg

import "core:testing"

@(test)
test_md5_auth_response :: proc(t: ^testing.T) {
	// Golden value: psql sends this for user "odin", password "odin_pg_test",
	// salt 0x01020304. Independently computed:
	//   inner = md5("odin_pg_test" + "odin") = md5("odin_pg_testodin")
	//   outer = "md5" + md5(hex(inner) + salt)
	out: [MD5_RESPONSE_LEN]u8
	got := md5_auth_response(&out, "odin", "odin_pg_test", {0x01, 0x02, 0x03, 0x04})
	testing.expect_value(t, len(got), MD5_RESPONSE_LEN)
	testing.expect_value(t, got[:3], "md5")
	testing.expect_value(t, got, "md5e6cb3e5a566e18491185a364c8d979a2")
}
