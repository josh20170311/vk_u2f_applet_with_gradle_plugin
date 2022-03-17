package com.josh.vku2f;

public class CTAP2ErrorCode {
    public static final byte CTAP1_ERR_SUCCESS = (byte) 0x00;
    public static final byte CTAP1_ERR_INVALID_COMMAND = (byte) 0x01;
    public static final byte CTAP1_ERR_INVALID_PARAMETER = (byte) 0x02;
    public static final byte CTAP1_ERR_INVALID_LENGTH = (byte) 0x03;
    public static final byte CTAP1_ERR_INVALID_SEQ = (byte) 0x04;
    public static final byte CTAP1_ERR_TIMEOUT = (byte) 0x05;
    public static final byte CTAP1_ERR_CHANNEL_BUSY = (byte) 0x06;
    public static final byte CTAP1_ERR_LOCK_REQUIRED = (byte) 0x0A;
    public static final byte CTAP1_ERR_INVALID_CHANNEL = (byte) 0x0B;
    public static final byte CTAP1_ERR_OTHER = (byte) 0x7F;

    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = (byte) 0x11;
    public static final byte CTAP2_ERR_INVALID_CBOR = (byte) 0x12;
    public static final byte CTAP2_ERR_MISSING_PARAMETER = (byte) 0x14;
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = (byte) 0x15;
    public static final byte CTAP2_ERR_UNSUPPORTED_EXTENSION = (byte) 0x16;
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = (byte) 0x19;
    public static final byte CTAP2_ERR_PROCESSING = (byte) 0x21;
    public static final byte CTAP2_ERR_INVALID_CREDENTIAL = (byte) 0x22;
    public static final byte CTAP2_ERR_USER_ACTION_PENDING = (byte) 0x23;
    public static final byte CTAP2_ERR_OPERATION_PENDING = (byte) 0x24;
    public static final byte CTAP2_ERR_NO_OPERATIONS = (byte) 0x25;
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = (byte) 0x26;
    public static final byte CTAP2_ERR_OPERATION_DENIED = (byte) 0x27;
    public static final byte CTAP2_ERR_KEY_STORE_FULL = (byte) 0x28;
    public static final byte CTAP2_ERR_NO_OPERATION_PENDING = (byte) 0x2A;
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = (byte) 0x2B;
    public static final byte CTAP2_ERR_INVALID_OPTION = (byte) 0x2C;
    public static final byte CTAP2_ERR_KEEPALIVE_CANCEL = (byte) 0x2D;
    public static final byte CTAP2_ERR_NO_CREDENTIALS = (byte) 0x2E;
    public static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = (byte) 0x2F;
    public static final byte CTAP2_ERR_NOT_ALLOWED = (byte) 0x30;
    public static final byte CTAP2_ERR_PIN_INVALID = (byte) 0x31;
    public static final byte CTAP2_ERR_PIN_BLOCKED = (byte) 0x32;
    public static final byte CTAP2_ERR_PIN_AUTH_INVALID = (byte) 0x33;
    public static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = (byte) 0x34;
    public static final byte CTAP2_ERR_PIN_NOT_SET = (byte) 0x35;
    public static final byte CTAP2_ERR_PIN_REQUIRED = (byte) 0x36;
    public static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = (byte) 0x37;
    public static final byte CTAP2_ERR_PIN_TOKEN_EXPIRED = (byte) 0x38;
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = (byte) 0x39;
    public static final byte CTAP2_ERR_ACTION_TIMEOUT = (byte) 0x3A;
    public static final byte CTAP2_ERR_UP_REQUIRED = (byte) 0x3B;
}
