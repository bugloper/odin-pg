package pg

import "core:testing"

@(test)
test_smoke :: proc(t: ^testing.T) {
	testing.expect_value(t, PROTOCOL_VERSION_MAJOR, 3)
}
