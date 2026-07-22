// PostgreSQL wire protocol (v3.0) constants shared by the proto_*.odin codec
// files. The codec layer is pure: it operates on []byte and the Stream
// vtable only, and must never import core:net (enforced in CI).
//
// Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
package pg

// The protocol version sent in StartupMessage: major 3, minor 0.
// Version 3.2 (PostgreSQL 18) is a compatible extension whose headline
// change is 256-bit cancel keys; BackendKeyData is stored as []byte and
// CancelRequest writes variable-length keys so opting in later is additive.
PROTOCOL_VERSION :: u32(3 << 16 | 0)

// Magic "versions" carried in the length-prefixed startup packet in place
// of a protocol version.
SSL_REQUEST_CODE :: u32(80877103)
CANCEL_REQUEST_CODE :: u32(80877102)
GSSENC_REQUEST_CODE :: u32(80877104)

// Upper bound on a single backend message body, guarding against a
// malicious or corrupt length prefix. Override with
// -define:ODIN_PG_MAX_MESSAGE_SIZE=n.
MAX_MESSAGE_SIZE :: #config(ODIN_PG_MAX_MESSAGE_SIZE, 64 << 20)

// Backend (server → client) message type bytes.
Backend_Msg :: enum u8 {
	Authentication             = 'R',
	Backend_Key_Data           = 'K',
	Bind_Complete              = '2',
	Close_Complete             = '3',
	Command_Complete           = 'C',
	Copy_Both_Response         = 'W',
	Copy_Data                  = 'd',
	Copy_Done                  = 'c',
	Copy_In_Response           = 'G',
	Copy_Out_Response          = 'H',
	Data_Row                   = 'D',
	Empty_Query_Response       = 'I',
	Error_Response             = 'E',
	Function_Call_Response     = 'V',
	Negotiate_Protocol_Version = 'v',
	No_Data                    = 'n',
	Notice_Response            = 'N',
	Notification_Response      = 'A',
	Parameter_Description      = 't',
	Parameter_Status           = 'S',
	Parse_Complete             = '1',
	Portal_Suspended           = 's',
	Ready_For_Query            = 'Z',
	Row_Description            = 'T',
}

// Frontend (client → server) message type bytes. StartupMessage,
// SSLRequest, and CancelRequest have no type byte (length-prefixed only).
Frontend_Msg :: enum u8 {
	Bind          = 'B',
	Close         = 'C',
	Copy_Data     = 'd',
	Copy_Done     = 'c',
	Copy_Fail     = 'f',
	Describe      = 'D',
	Execute       = 'E',
	Flush         = 'H',
	Function_Call = 'F',
	Parse         = 'P',
	// Carries PasswordMessage, SASLInitialResponse, SASLResponse,
	// GSSResponse — all share the 'p' type byte.
	Password      = 'p',
	Query         = 'Q',
	Sync          = 'S',
	Terminate     = 'X',
}

// Authentication request codes carried in the Authentication ('R') message.
Auth_Code :: enum u32 {
	Ok                 = 0,
	Kerberos_V5        = 2,
	Cleartext_Password = 3,
	MD5_Password       = 5,
	GSS                = 7,
	GSS_Continue       = 8,
	SSPI               = 9,
	SASL               = 10,
	SASL_Continue      = 11,
	SASL_Final         = 12,
}

// Transaction status carried in ReadyForQuery.
Txn_Status :: enum u8 {
	Idle       = 'I',
	In_Txn     = 'T',
	Failed_Txn = 'E',
}

// Format codes used in Bind parameter/result format lists and in
// RowDescription fields.
Format :: enum i16 {
	Text   = 0,
	Binary = 1,
}
