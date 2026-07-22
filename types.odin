package pg

// Typed column access. get(row, T, col) decodes one cell into an Odin value,
// handling both wire formats: text (what plain queries return today) and
// binary (used once prepared statements negotiate per-column formats).
//
// NULL handling: plain T fails with .Null_Value; Maybe(T) yields nil.
// Strings and byte slices are CLONED into the given allocator — the
// zero-copy escape hatch is row_cell/row_text.

import "base:intrinsics"
import "base:runtime"
import "core:encoding/endian"
import "core:encoding/uuid"
import "core:mem"
import "core:strconv"
import "core:strings"
import "core:time"
import "core:time/datetime"

// Microseconds between the Unix epoch (1970-01-01) and the PostgreSQL
// epoch (2000-01-01), both UTC.
@(private)
PG_EPOCH_UNIX_MICROS :: i64(946_684_800_000_000)

get :: proc(row: Row, $T: typeid, col: int, allocator := context.allocator) -> (value: T, err: Error) {
	if col < 0 || col >= len(row.cells) {
		return {}, Driver_Error.Column_Out_Of_Range
	}
	cell := row.cells[col]

	field: Field
	if col < len(row.fields) {
		field = row.fields[col]
	}
	return decode_value(T, cell.data, cell.is_null, field, allocator)
}

// decode_value handles NULL (Maybe(T) → nil, plain T → .Null_Value) and
// forwards to the format decoders. Also used for array elements.
@(private)
decode_value :: proc($T: typeid, data: []byte, is_null: bool, field: Field, allocator: mem.Allocator) -> (value: T, err: Error) {
	when intrinsics.type_is_union(T) {
		when intrinsics.type_union_variant_count(T) == 1 {
			if is_null {
				return nil, nil
			}
			inner := decode_value(intrinsics.type_variant_type_of(T, 0), data, false, field, allocator) or_return
			value = inner
			return value, nil
		} else {
			#panic("pg.get: only Maybe(T)-shaped unions are supported")
		}
	} else {
		if is_null {
			return {}, Driver_Error.Null_Value
		}
		return decode_cell(T, data, field, allocator)
	}
}

get_by_name :: proc(row: Row, $T: typeid, name: string, allocator := context.allocator) -> (value: T, err: Error) {
	col, ok := column_index(row, name)
	if !ok {
		return {}, Driver_Error.No_Such_Column
	}
	return get(row, T, col, allocator)
}

// scan decodes one row into pointer destinations, in column order:
//
//	id: i64; name: Maybe(string)
//	pg.scan(row, &id, &name) or_return
scan :: proc(row: Row, dests: ..any, allocator := context.allocator) -> Error {
	if len(dests) > len(row.cells) {
		return Driver_Error.Column_Out_Of_Range
	}
	for dest, i in dests {
		ti := runtime.type_info_base(type_info_of(dest.id))
		ptr_info, is_ptr := ti.variant.(runtime.Type_Info_Pointer)
		if !is_ptr || ptr_info.elem == nil {
			return Driver_Error.Unsupported_Type
		}
		scan_into(row, i, (^rawptr)(dest.data)^, ptr_info.elem.id, allocator) or_return
	}
	return nil
}

// scan_into decodes one column into an any-wrapped pointer; shared by scan
// and scan_struct.
@(private)
scan_into :: proc(row: Row, i: int, data: rawptr, id: typeid, allocator := context.allocator) -> Error {
	switch id {
	case bool:
		(^bool)(data)^ = get(row, bool, i, allocator) or_return
	case i16:
		(^i16)(data)^ = get(row, i16, i, allocator) or_return
	case i32:
		(^i32)(data)^ = get(row, i32, i, allocator) or_return
	case i64:
		(^i64)(data)^ = get(row, i64, i, allocator) or_return
	case int:
		(^int)(data)^ = get(row, int, i, allocator) or_return
	case u32:
		(^u32)(data)^ = get(row, u32, i, allocator) or_return
	case u64:
		(^u64)(data)^ = get(row, u64, i, allocator) or_return
	case uint:
		(^uint)(data)^ = get(row, uint, i, allocator) or_return
	case f32:
		(^f32)(data)^ = get(row, f32, i, allocator) or_return
	case f64:
		(^f64)(data)^ = get(row, f64, i, allocator) or_return
	case string:
		(^string)(data)^ = get(row, string, i, allocator) or_return
	case []byte:
		(^[]byte)(data)^ = get(row, []byte, i, allocator) or_return
	case uuid.Identifier:
		(^uuid.Identifier)(data)^ = get(row, uuid.Identifier, i, allocator) or_return
	case time.Time:
		(^time.Time)(data)^ = get(row, time.Time, i, allocator) or_return
	case datetime.Date:
		(^datetime.Date)(data)^ = get(row, datetime.Date, i, allocator) or_return
	case Maybe(bool):
		(^Maybe(bool))(data)^ = get(row, Maybe(bool), i, allocator) or_return
	case Maybe(i16):
		(^Maybe(i16))(data)^ = get(row, Maybe(i16), i, allocator) or_return
	case Maybe(i32):
		(^Maybe(i32))(data)^ = get(row, Maybe(i32), i, allocator) or_return
	case Maybe(i64):
		(^Maybe(i64))(data)^ = get(row, Maybe(i64), i, allocator) or_return
	case Maybe(int):
		(^Maybe(int))(data)^ = get(row, Maybe(int), i, allocator) or_return
	case Maybe(f32):
		(^Maybe(f32))(data)^ = get(row, Maybe(f32), i, allocator) or_return
	case Maybe(f64):
		(^Maybe(f64))(data)^ = get(row, Maybe(f64), i, allocator) or_return
	case Maybe(string):
		(^Maybe(string))(data)^ = get(row, Maybe(string), i, allocator) or_return
	case Maybe([]byte):
		(^Maybe([]byte))(data)^ = get(row, Maybe([]byte), i, allocator) or_return
	case Maybe(uuid.Identifier):
		(^Maybe(uuid.Identifier))(data)^ = get(row, Maybe(uuid.Identifier), i, allocator) or_return
	case Maybe(time.Time):
		(^Maybe(time.Time))(data)^ = get(row, Maybe(time.Time), i, allocator) or_return
	case Maybe(datetime.Date):
		(^Maybe(datetime.Date))(data)^ = get(row, Maybe(datetime.Date), i, allocator) or_return
	case Numeric:
		(^Numeric)(data)^ = get(row, Numeric, i, allocator) or_return
	case []bool:
		(^[]bool)(data)^ = get(row, []bool, i, allocator) or_return
	case []i16:
		(^[]i16)(data)^ = get(row, []i16, i, allocator) or_return
	case []i32:
		(^[]i32)(data)^ = get(row, []i32, i, allocator) or_return
	case []i64:
		(^[]i64)(data)^ = get(row, []i64, i, allocator) or_return
	case []f32:
		(^[]f32)(data)^ = get(row, []f32, i, allocator) or_return
	case []f64:
		(^[]f64)(data)^ = get(row, []f64, i, allocator) or_return
	case []string:
		(^[]string)(data)^ = get(row, []string, i, allocator) or_return
	case:
		return Driver_Error.Unsupported_Type
	}
	return nil
}

@(private)
decode_cell :: proc($T: typeid, data: []byte, field: Field, allocator: mem.Allocator) -> (value: T, err: Error) {
	binary := field.format == .Binary

	when T == bool {
		if binary {
			if len(data) != 1 {
				return {}, Driver_Error.Type_Mismatch
			}
			return data[0] != 0, nil
		}
		switch string(data) {
		case "t", "true":
			return true, nil
		case "f", "false":
			return false, nil
		}
		return {}, Driver_Error.Type_Mismatch
	} else when intrinsics.type_is_integer(T) && !intrinsics.type_is_unsigned(T) {
		v := decode_i64(data, binary) or_return
		if i64(T(v)) != v {
			return {}, Driver_Error.Out_Of_Range
		}
		return T(v), nil
	} else when intrinsics.type_is_integer(T) && intrinsics.type_is_unsigned(T) {
		v := decode_i64(data, binary) or_return
		if v < 0 {
			return {}, Driver_Error.Out_Of_Range
		}
		u := u64(v)
		if u64(T(u)) != u {
			return {}, Driver_Error.Out_Of_Range
		}
		return T(u), nil
	} else when T == f32 || T == f64 {
		if binary {
			switch len(data) {
			case 4:
				bits, _ := endian.get_u32(data, .Big)
				return T(transmute(f32)bits), nil
			case 8:
				bits, _ := endian.get_u64(data, .Big)
				return T(transmute(f64)bits), nil
			}
			return {}, Driver_Error.Type_Mismatch
		}
		v, ok := strconv.parse_f64(string(data))
		if !ok {
			return {}, Driver_Error.Type_Mismatch
		}
		return T(v), nil
	} else when T == string {
		_ = binary // text and binary wire forms are both raw bytes
		s := strings.clone(string(data), allocator) or_return
		return s, nil
	} else when T == []byte {
		if !binary && field.type_oid == BYTEA {
			return decode_bytea_text(data, allocator)
		}
		out := make([]byte, len(data), allocator) or_return
		copy(out, data)
		return out, nil
	} else when T == uuid.Identifier {
		if binary {
			if len(data) != 16 {
				return {}, Driver_Error.Type_Mismatch
			}
			id: uuid.Identifier
			copy(id[:], data)
			return id, nil
		}
		id, read_err := uuid.read(string(data))
		if read_err != nil {
			return {}, Driver_Error.Type_Mismatch
		}
		return id, nil
	} else when T == time.Time {
		if binary {
			if len(data) != 8 {
				return {}, Driver_Error.Type_Mismatch
			}
			micros, _ := endian.get_i64(data, .Big)
			return pg_micros_to_time(micros)
		}
		return parse_timestamp_text(string(data))
	} else when T == datetime.Date {
		if binary {
			if len(data) != 4 {
				return {}, Driver_Error.Type_Mismatch
			}
			days, _ := endian.get_i32(data, .Big)
			return pg_days_to_date(days)
		}
		return parse_date_text(string(data))
	} else when T == Numeric {
		if binary {
			return parse_numeric_binary(data, allocator)
		}
		return parse_numeric_text(string(data), allocator)
	} else when intrinsics.type_is_slice(T) {
		// []byte is matched above; every other slice type is a PostgreSQL
		// array decoded element-wise. Nested slices (e.g. [][]i64) match
		// multi-dimensional arrays of the same rank.
		return decode_array(T, data, field, binary, allocator)
	} else {
		#panic("pg.get: unsupported destination type")
	}
}

@(private)
decode_i64 :: proc(data: []byte, binary: bool) -> (v: i64, err: Error) {
	if binary {
		switch len(data) {
		case 2:
			x, _ := endian.get_i16(data, .Big)
			return i64(x), nil
		case 4:
			x, _ := endian.get_i32(data, .Big)
			return i64(x), nil
		case 8:
			x, _ := endian.get_i64(data, .Big)
			return x, nil
		}
		return 0, Driver_Error.Type_Mismatch
	}
	x, ok := strconv.parse_i64(string(data))
	if !ok {
		return 0, Driver_Error.Type_Mismatch
	}
	return x, nil
}

// decode_bytea_text decodes the "\x0a0b…" hex form (PostgreSQL 9+ default).
@(private)
decode_bytea_text :: proc(data: []byte, allocator: mem.Allocator) -> (out: []byte, err: Error) {
	if len(data) < 2 || data[0] != '\\' || data[1] != 'x' || len(data) % 2 != 0 {
		return nil, Driver_Error.Type_Mismatch
	}
	hex := data[2:]
	out = make([]byte, len(hex) / 2, allocator) or_return
	for i in 0 ..< len(out) {
		hi, hi_ok := hex_nibble(hex[i * 2])
		lo, lo_ok := hex_nibble(hex[i * 2 + 1])
		if !hi_ok || !lo_ok {
			delete(out, allocator)
			return nil, Driver_Error.Type_Mismatch
		}
		out[i] = hi << 4 | lo
	}
	return out, nil
}

@(private)
hex_nibble :: proc(c: u8) -> (v: u8, ok: bool) {
	switch c {
	case '0' ..= '9':
		return c - '0', true
	case 'a' ..= 'f':
		return c - 'a' + 10, true
	case 'A' ..= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

@(private)
pg_micros_to_time :: proc(pg_micros: i64) -> (t: time.Time, err: Error) {
	// PG's ±infinity sentinels and values beyond time.Time's i64-nanosecond
	// range (~year 1678..2262) cannot be represented.
	unix_micros := pg_micros + PG_EPOCH_UNIX_MICROS
	if unix_micros > max(i64) / 1000 || unix_micros < min(i64) / 1000 {
		return {}, Driver_Error.Out_Of_Range
	}
	return time.unix(0, unix_micros * 1000), nil
}

@(private)
pg_days_to_date :: proc(pg_days: i32) -> (date: datetime.Date, err: Error) {
	epoch, _ := datetime.date_to_ordinal(datetime.Date{year = 2000, month = 1, day = 1})
	d, conv_err := datetime.ordinal_to_date(epoch + datetime.Ordinal(pg_days))
	if conv_err != nil {
		return {}, Driver_Error.Out_Of_Range
	}
	return d, nil
}

// parse_date_text parses "YYYY-MM-DD". BC dates and infinities are out of
// range for datetime.Date semantics here.
@(private)
parse_date_text :: proc(s: string) -> (date: datetime.Date, err: Error) {
	pos := 0
	year := parse_number(s, &pos, '-') or_return
	month := parse_number(s, &pos, '-') or_return
	day := parse_number(s, &pos, 0) or_return
	if pos != len(s) {
		return {}, Driver_Error.Type_Mismatch // trailing " BC" etc.
	}
	date = datetime.Date {
		year   = i64(year),
		month  = i8(month),
		day    = i8(day),
	}
	if validate_err := datetime.validate_date(date); validate_err != nil {
		return {}, Driver_Error.Type_Mismatch
	}
	return date, nil
}

// parse_timestamp_text parses ISO DateStyle timestamps:
// "YYYY-MM-DD HH:MM:SS[.ffffff][±HH[:MM[:SS]]]" — with the offset present
// for timestamptz. The result is UTC.
@(private)
parse_timestamp_text :: proc(s: string) -> (t: time.Time, err: Error) {
	switch s {
	case "infinity", "-infinity":
		return {}, Driver_Error.Out_Of_Range
	}
	if strings.has_suffix(s, " BC") {
		return {}, Driver_Error.Out_Of_Range
	}

	pos := 0
	year := parse_number(s, &pos, '-') or_return
	month := parse_number(s, &pos, '-') or_return
	day := parse_number(s, &pos, ' ') or_return
	hour := parse_number(s, &pos, ':') or_return
	minute := parse_number(s, &pos, ':') or_return
	second := parse_number(s, &pos, 0) or_return

	nsec := 0
	if pos < len(s) && s[pos] == '.' {
		pos += 1
		start := pos
		for pos < len(s) && s[pos] >= '0' && s[pos] <= '9' {
			pos += 1
		}
		digits := s[start:pos]
		if digits == "" || len(digits) > 9 {
			return {}, Driver_Error.Type_Mismatch
		}
		frac, _ := strconv.parse_int(digits)
		for _ in 0 ..< 9 - len(digits) {
			frac *= 10
		}
		nsec = frac
	}

	offset_seconds := 0
	if pos < len(s) && (s[pos] == '+' || s[pos] == '-') {
		negative := s[pos] == '-'
		pos += 1
		oh := parse_number(s, &pos, 0) or_return
		om, os := 0, 0
		if pos < len(s) && s[pos] == ':' {
			pos += 1
			om = parse_number(s, &pos, 0) or_return
		}
		if pos < len(s) && s[pos] == ':' {
			pos += 1
			os = parse_number(s, &pos, 0) or_return
		}
		offset_seconds = oh * 3600 + om * 60 + os
		if negative {
			offset_seconds = -offset_seconds
		}
	}
	if pos != len(s) {
		return {}, Driver_Error.Type_Mismatch
	}

	local, ok := time.components_to_time(year, month, day, hour, minute, second, nsec)
	if !ok {
		return {}, Driver_Error.Out_Of_Range
	}
	return time.time_add(local, -time.Duration(offset_seconds) * time.Second), nil
}

// parse_number reads digits up to the separator (consuming it) or, with
// sep == 0, up to the first non-digit.
@(private = "file")
parse_number :: proc(s: string, pos: ^int, sep: u8) -> (v: int, err: Error) {
	start := pos^
	for pos^ < len(s) && s[pos^] >= '0' && s[pos^] <= '9' {
		pos^ += 1
	}
	if pos^ == start {
		return 0, Driver_Error.Type_Mismatch
	}
	v, _ = strconv.parse_int(s[start:pos^])
	if sep != 0 {
		if pos^ >= len(s) || s[pos^] != sep {
			return 0, Driver_Error.Type_Mismatch
		}
		pos^ += 1
	}
	return v, nil
}
