package pg

// Extended type support: PostgreSQL arrays (1-D and rectangular multi-D as
// nested slices), exact NUMERIC values, JSON/JSONB unmarshalling, and struct
// scanning.

import "base:intrinsics"
import "core:encoding/json"
import "core:mem"
import "core:reflect"
import "core:strconv"
import "core:strings"

// Referenced only inside generic procs, which the checker skips until
// instantiation; keep the imports alive for -vet.
_ :: json
_ :: reflect

// --- Arrays ---

// decode_array decodes a PostgreSQL array into nested Odin slices matching
// the wire rank: []E for 1-D, [][]E for 2-D, etc. Element strings/slices
// are cloned into allocator (as is each slice); NULL elements require E to
// be Maybe(…), otherwise .Null_Value. Rank mismatch is .Unsupported_Type.
// []byte is always a leaf (bytea), never an extra array dimension.
@(private)
decode_array :: proc($T: typeid, data: []byte, field: Field, binary: bool, allocator: mem.Allocator) -> (out: T, err: Error) where intrinsics.type_is_slice(T) {
	if binary {
		return decode_array_binary(T, data, allocator)
	}
	return decode_array_text(T, data, field, allocator)
}

// array_rank is the number of nested slice dimensions in T, treating []byte
// as a leaf (so [][]byte is rank 1 — a 1-D array of bytea).
@(private)
array_rank :: proc($T: typeid) -> int {
	when !intrinsics.type_is_slice(T) || T == []byte || T == []u8 {
		return 0
	} else {
		return 1 + array_rank(intrinsics.type_elem_type(T))
	}
}

@(private)
decode_array_binary :: proc($T: typeid, data: []byte, allocator: mem.Allocator) -> (out: T, err: Error) {
	pos := 0
	ndim, ok1 := cursor_i32(data, &pos)
	_, ok2 := cursor_i32(data, &pos) // hasnull flag (we discover NULLs per element)
	elem_oid_raw, ok3 := cursor_u32(data, &pos)
	if !ok1 || !ok2 || !ok3 || ndim < 0 {
		return nil, Driver_Error.Type_Mismatch
	}
	if ndim == 0 {
		return make(T, 0, allocator) or_return, nil
	}
	if int(ndim) != array_rank(T) {
		return nil, Driver_Error.Unsupported_Type
	}

	dims := make([]int, int(ndim), context.temp_allocator)
	for i in 0 ..< int(ndim) {
		count, ok4 := cursor_i32(data, &pos)
		_, ok5 := cursor_i32(data, &pos) // lower bound (ignored)
		if !ok4 || !ok5 || count < 0 {
			return nil, Driver_Error.Type_Mismatch
		}
		dims[i] = int(count)
	}

	elem_field := Field {
		type_oid = Oid(elem_oid_raw),
		format   = .Binary,
	}
	return decode_array_binary_level(T, data, &pos, dims, 0, elem_field, allocator)
}

@(private)
decode_array_binary_level :: proc(
	$T: typeid,
	data: []byte,
	pos: ^int,
	dims: []int,
	dim_idx: int,
	elem_field: Field,
	allocator: mem.Allocator,
) -> (out: T, err: Error) where intrinsics.type_is_slice(T) {
	E :: intrinsics.type_elem_type(T)
	count := dims[dim_idx]
	elems := make(T, count, allocator) or_return

	// Nested dimension: recurse. []byte/[]u8 are leaves even though slices.
	when intrinsics.type_is_slice(E) && E != []byte && E != []u8 {
		for i in 0 ..< count {
			elems[i] = decode_array_binary_level(E, data, pos, dims, dim_idx + 1, elem_field, allocator) or_return
		}
	} else {
		for i in 0 ..< count {
			length, len_ok := cursor_i32(data, pos)
			if !len_ok {
				return nil, Driver_Error.Type_Mismatch
			}
			if length == -1 {
				elems[i] = decode_value(E, nil, true, elem_field, allocator) or_return
				continue
			}
			bytes, bytes_ok := cursor_bytes(data, pos, int(length))
			if !bytes_ok {
				return nil, Driver_Error.Type_Mismatch
			}
			elems[i] = decode_value(E, bytes, false, elem_field, allocator) or_return
		}
	}
	return elems, nil
}

// decode_array_text parses the '{a,b,NULL,"c d"}' / '{{1,2},{3,4}}' form.
@(private)
decode_array_text :: proc($T: typeid, data: []byte, field: Field, allocator: mem.Allocator) -> (out: T, err: Error) {
	s := string(data)
	// Optional explicit-bounds prefix: [1:3]={…} or [1:2][1:2]={{…},{…}}
	if len(s) > 0 && s[0] == '[' {
		eq := strings.index_byte(s, '=')
		if eq < 0 {
			return nil, Driver_Error.Type_Mismatch
		}
		s = s[eq + 1:]
	}
	if len(s) < 2 || s[0] != '{' || s[len(s) - 1] != '}' {
		return nil, Driver_Error.Type_Mismatch
	}

	// Rank mismatch: a 1-D destination cannot accept nested braces, and a
	// multi-D destination requires nesting (empty {} is allowed for any rank).
	inner := s[1:len(s) - 1]
	rank := array_rank(T)
	if rank == 1 && strings.index_byte(inner, '{') >= 0 {
		return nil, Driver_Error.Unsupported_Type
	}
	if rank > 1 && inner != "" && strings.index_byte(inner, '{') < 0 {
		return nil, Driver_Error.Unsupported_Type
	}

	elem_field := Field {
		type_oid = elem_oid(field.type_oid),
		format   = .Text,
	}
	return decode_array_text_level(T, s, elem_field, allocator)
}

@(private)
decode_array_text_level :: proc(
	$T: typeid,
	literal: string,
	elem_field: Field,
	allocator: mem.Allocator,
) -> (out: T, err: Error) where intrinsics.type_is_slice(T) {
	if len(literal) < 2 || literal[0] != '{' || literal[len(literal) - 1] != '}' {
		return nil, Driver_Error.Type_Mismatch
	}
	inner := literal[1:len(literal) - 1]
	E :: intrinsics.type_elem_type(T)
	elems := make([dynamic]E, allocator)
	defer if err != nil {
		delete(elems)
	}
	if inner == "" {
		return elems[:], nil
	}

	pos := 0
	for pos <= len(inner) {
		// Nested sub-array element.
		when intrinsics.type_is_slice(E) && E != []byte && E != []u8 {
			if pos >= len(inner) || inner[pos] != '{' {
				return nil, Driver_Error.Type_Mismatch
			}
			end, span_ok := array_text_span(inner, pos)
			if !span_ok {
				return nil, Driver_Error.Type_Mismatch
			}
			sub := decode_array_text_level(E, inner[pos:end], elem_field, allocator) or_return
			append(&elems, sub)
			pos = end
		} else {
			sb := strings.builder_make(context.temp_allocator)
			is_null := false
			if pos < len(inner) && inner[pos] == '"' {
				// Quoted element with backslash escapes.
				pos += 1
				closed := false
				for pos < len(inner) {
					c := inner[pos]
					if c == '\\' && pos + 1 < len(inner) {
						strings.write_byte(&sb, inner[pos + 1])
						pos += 2
						continue
					}
					if c == '"' {
						pos += 1
						closed = true
						break
					}
					strings.write_byte(&sb, c)
					pos += 1
				}
				if !closed {
					return nil, Driver_Error.Type_Mismatch
				}
			} else {
				start := pos
				for pos < len(inner) && inner[pos] != ',' {
					pos += 1
				}
				raw := inner[start:pos]
				if raw == "NULL" {
					is_null = true
				} else {
					strings.write_string(&sb, raw)
				}
			}
			elem_text := strings.to_string(sb)
			elem := decode_value(E, transmute([]byte)elem_text, is_null, elem_field, allocator) or_return
			append(&elems, elem)
		}

		if pos >= len(inner) {
			break
		}
		if inner[pos] != ',' {
			return nil, Driver_Error.Type_Mismatch
		}
		pos += 1
	}
	return elems[:], nil
}

// array_text_span returns the exclusive end index of a balanced `{…}` starting
// at start, respecting quotes and backslash escapes.
@(private)
array_text_span :: proc(s: string, start: int) -> (end: int, ok: bool) {
	if start >= len(s) || s[start] != '{' {
		return 0, false
	}
	depth := 0
	in_quote := false
	i := start
	for i < len(s) {
		c := s[i]
		if in_quote {
			if c == '\\' && i + 1 < len(s) {
				i += 2
				continue
			}
			if c == '"' {
				in_quote = false
			}
			i += 1
			continue
		}
		switch c {
		case '"':
			in_quote = true
		case '{':
			depth += 1
		case '}':
			depth -= 1
			if depth == 0 {
				return i + 1, true
			}
		}
		i += 1
	}
	return 0, false
}

// elem_oid maps a built-in array OID to its element OID (0 if unknown —
// element decoders that don't inspect the OID still work).
@(private)
elem_oid :: proc(array_oid: Oid) -> Oid {
	switch array_oid {
	case BOOL_ARRAY:
		return BOOL
	case BYTEA_ARRAY:
		return BYTEA
	case INT2_ARRAY:
		return INT2
	case INT4_ARRAY:
		return INT4
	case INT8_ARRAY:
		return INT8
	case TEXT_ARRAY:
		return TEXT
	case VARCHAR_ARRAY:
		return VARCHAR
	case FLOAT4_ARRAY:
		return FLOAT4
	case FLOAT8_ARRAY:
		return FLOAT8
	case DATE_ARRAY:
		return DATE
	case TIMESTAMP_ARRAY:
		return TIMESTAMP
	case TIMESTAMPTZ_ARRAY:
		return TIMESTAMPTZ
	case NUMERIC_ARRAY:
		return NUMERIC
	case UUID_ARRAY:
		return UUID
	case JSONB_ARRAY:
		return JSONB
	}
	return Oid(0)
}

// --- NUMERIC ---

Numeric_Kind :: enum u8 {
	Finite,
	NaN,
	Pos_Inf,
	Neg_Inf,
}

// Numeric is an exact representation of a PostgreSQL numeric value:
// sign × Σ digits[i] × 10000^(weight−i), displayed with dscale fractional
// decimal digits. digits is allocator-owned; release with numeric_destroy.
Numeric :: struct {
	kind:     Numeric_Kind,
	negative: bool,
	weight:   i16, // base-10000 exponent of digits[0]
	dscale:   u16, // decimal digits after the point
	digits:   []u16, // base-10000, most significant first; empty = zero
}

numeric_destroy :: proc(n: ^Numeric, allocator := context.allocator) {
	delete(n.digits, allocator)
	n^ = {}
}

// parse_numeric_text parses the text form ("-12345.6789", "NaN",
// "Infinity", "-Infinity").
@(private)
parse_numeric_text :: proc(s: string, allocator: mem.Allocator) -> (n: Numeric, err: Error) {
	switch s {
	case "NaN":
		return Numeric{kind = .NaN}, nil
	case "Infinity":
		return Numeric{kind = .Pos_Inf}, nil
	case "-Infinity":
		return Numeric{kind = .Neg_Inf}, nil
	}

	rest := s
	if len(rest) > 0 && (rest[0] == '-' || rest[0] == '+') {
		n.negative = rest[0] == '-'
		rest = rest[1:]
	}
	int_part := rest
	frac_part := ""
	if dot := strings.index_byte(rest, '.'); dot >= 0 {
		int_part = rest[:dot]
		frac_part = rest[dot + 1:]
	}
	if int_part == "" && frac_part == "" {
		return {}, Driver_Error.Type_Mismatch
	}
	for c in transmute([]byte)int_part {
		if c < '0' || c > '9' {
			return {}, Driver_Error.Type_Mismatch
		}
	}
	for c in transmute([]byte)frac_part {
		if c < '0' || c > '9' {
			return {}, Driver_Error.Type_Mismatch
		}
	}
	n.dscale = u16(len(frac_part))

	// Group the decimal digits into base-10000 words: the integer part is
	// left-padded, the fraction right-padded, so groups align at the point.
	int_trimmed := strings.trim_left(int_part, "0")
	int_groups := (len(int_trimmed) + 3) / 4
	frac_groups := (len(frac_part) + 3) / 4
	n.weight = i16(int_groups - 1)

	groups := make([dynamic]u16, 0, int_groups + frac_groups, context.temp_allocator)
	if int_groups > 0 {
		// First (most significant) group may be short.
		first_len := len(int_trimmed) - (int_groups - 1) * 4
		g, _ := strconv.parse_uint(int_trimmed[:first_len])
		append(&groups, u16(g))
		for i in 0 ..< int_groups - 1 {
			start := first_len + i * 4
			g2, _ := strconv.parse_uint(int_trimmed[start:start + 4])
			append(&groups, u16(g2))
		}
	}
	for i in 0 ..< frac_groups {
		start := i * 4
		end := min(start + 4, len(frac_part))
		chunk := frac_part[start:end]
		g, _ := strconv.parse_uint(chunk)
		// Right-pad short trailing group to a full base-10000 word.
		for _ in 0 ..< 4 - len(chunk) {
			g *= 10
		}
		append(&groups, u16(g))
	}

	// Normalize: strip leading/trailing zero words (weight tracks leading).
	start := 0
	for start < len(groups) && groups[start] == 0 {
		start += 1
		n.weight -= 1
	}
	end := len(groups)
	for end > start && groups[end - 1] == 0 {
		end -= 1
	}
	if end > start {
		n.digits = make([]u16, end - start, allocator) or_return
		copy(n.digits, groups[start:end])
	} else {
		n.weight = 0
		n.negative = false // PostgreSQL has no negative zero
	}
	return n, nil
}

// parse_numeric_binary decodes the wire format: ndigits/weight/sign/dscale
// (i16be each) followed by the base-10000 digits.
@(private)
parse_numeric_binary :: proc(data: []byte, allocator: mem.Allocator) -> (n: Numeric, err: Error) {
	pos := 0
	ndigits, ok1 := cursor_i16(data, &pos)
	weight, ok2 := cursor_i16(data, &pos)
	sign, ok3 := cursor_i16(data, &pos)
	dscale, ok4 := cursor_i16(data, &pos)
	if !ok1 || !ok2 || !ok3 || !ok4 || ndigits < 0 {
		return {}, Driver_Error.Type_Mismatch
	}
	switch u16(sign) {
	case 0x0000:
	case 0x4000:
		n.negative = true
	case 0xC000:
		return Numeric{kind = .NaN}, nil
	case 0xD000:
		return Numeric{kind = .Pos_Inf}, nil
	case 0xF000:
		return Numeric{kind = .Neg_Inf}, nil
	case:
		return {}, Driver_Error.Type_Mismatch
	}
	n.weight = weight
	n.dscale = u16(dscale)
	n.digits = make([]u16, int(ndigits), allocator) or_return
	for i in 0 ..< int(ndigits) {
		d, ok := cursor_i16(data, &pos)
		if !ok || d < 0 || d > 9999 {
			delete(n.digits, allocator)
			return {}, Driver_Error.Type_Mismatch
		}
		n.digits[i] = u16(d)
	}
	return n, nil
}

// numeric_to_string renders the exact decimal form (round-trips with the
// server's text output).
numeric_to_string :: proc(n: Numeric, allocator := context.allocator) -> string {
	switch n.kind {
	case .NaN:
		return strings.clone("NaN", allocator)
	case .Pos_Inf:
		return strings.clone("Infinity", allocator)
	case .Neg_Inf:
		return strings.clone("-Infinity", allocator)
	case .Finite:
	}

	sb := strings.builder_make(allocator)
	if n.negative {
		strings.write_byte(&sb, '-')
	}

	// Integer part: words 0..weight.
	if n.weight < 0 {
		strings.write_byte(&sb, '0')
	} else {
		for w in 0 ..= int(n.weight) {
			g := n.digits[w] if w < len(n.digits) else 0
			if w == 0 {
				strings.write_uint(&sb, uint(g))
			} else {
				write_group_padded(&sb, g)
			}
		}
	}

	// Fraction: dscale decimal digits starting at word weight+1.
	if n.dscale > 0 {
		strings.write_byte(&sb, '.')
		emitted := 0
		w := int(n.weight) + 1
		for emitted < int(n.dscale) {
			g := u16(0)
			if w >= 0 && w < len(n.digits) {
				g = n.digits[w]
			}
			buf: [4]u8
			buf[0] = '0' + u8(g / 1000)
			buf[1] = '0' + u8(g / 100 % 10)
			buf[2] = '0' + u8(g / 10 % 10)
			buf[3] = '0' + u8(g % 10)
			take := min(4, int(n.dscale) - emitted)
			strings.write_bytes(&sb, buf[:take])
			emitted += take
			w += 1
		}
	}
	return strings.to_string(sb)
}

@(private = "file")
write_group_padded :: proc(sb: ^strings.Builder, g: u16) {
	strings.write_byte(sb, '0' + u8(g / 1000))
	strings.write_byte(sb, '0' + u8(g / 100 % 10))
	strings.write_byte(sb, '0' + u8(g / 10 % 10))
	strings.write_byte(sb, '0' + u8(g % 10))
}

// numeric_to_f64 converts lossily (f64 has 53 bits of mantissa).
numeric_to_f64 :: proc(n: Numeric) -> f64 {
	switch n.kind {
	case .NaN:
		nan := transmute(f64)u64(0x7FF8_0000_0000_0000)
		return nan
	case .Pos_Inf:
		return transmute(f64)u64(0x7FF0_0000_0000_0000)
	case .Neg_Inf:
		return transmute(f64)u64(0xFFF0_0000_0000_0000)
	case .Finite:
	}
	value := 0.0
	scale := pow10000(int(n.weight))
	for d in n.digits {
		value += f64(d) * scale
		scale /= 10000
	}
	if n.negative {
		value = -value
	}
	return value
}

@(private = "file")
pow10000 :: proc(exp: int) -> f64 {
	result := 1.0
	if exp >= 0 {
		for _ in 0 ..< exp {
			result *= 10000
		}
	} else {
		for _ in 0 ..< -exp {
			result /= 10000
		}
	}
	return result
}

// --- JSON ---

// get_json unmarshals a json/jsonb column into T via core:encoding/json.
get_json :: proc(row: Row, $T: typeid, col: int, allocator := context.allocator) -> (value: T, err: Error) {
	data, is_null, cell_err := row_cell(row, col)
	if cell_err != nil {
		return {}, cell_err
	}
	if is_null {
		return {}, Driver_Error.Null_Value
	}
	bytes := data
	if col < len(row.fields) {
		field := row.fields[col]
		// Binary jsonb is a version byte (1) followed by the JSON text.
		if field.format == .Binary && field.type_oid == JSONB {
			if len(bytes) < 1 || bytes[0] != 1 {
				return {}, Driver_Error.Type_Mismatch
			}
			bytes = bytes[1:]
		}
	}
	if unmarshal_err := json.unmarshal(bytes, &value, allocator = allocator); unmarshal_err != nil {
		return {}, Driver_Error.Type_Mismatch
	}
	return value, nil
}

// --- Struct scanning ---

// scan_struct fills dest's fields from the row by column name. A field maps
// to the column named by its `db:"…"` tag, or by its own name when untagged;
// `db:"-"` skips the field. A tagged field with no matching column is
// .No_Such_Column; an untagged field with no match is skipped.
scan_struct :: proc(row: Row, dest: ^$T, allocator := context.allocator) -> Error where intrinsics.type_is_struct(T) {
	for field in reflect.struct_fields_zipped(T) {
		name := field.name
		tagged := false
		if db_tag, has_tag := reflect.struct_tag_lookup(field.tag, "db"); has_tag {
			if db_tag == "-" {
				continue
			}
			name = db_tag
			tagged = true
		}
		col, found := column_index_by_name(row, name)
		if !found {
			if tagged {
				return Driver_Error.No_Such_Column
			}
			continue
		}
		scan_into(row, col, rawptr(uintptr(dest) + field.offset), field.type.id, allocator) or_return
	}
	return nil
}

@(private = "file")
column_index_by_name :: proc(row: Row, name: string) -> (col: int, ok: bool) {
	return column_index(row, name)
}
