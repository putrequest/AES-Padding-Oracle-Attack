const std = @import("std");
const key = @import("./key.zig");
const debug = std.debug;
const aes = std.crypto.core.aes;

const block_length = aes.AesDecryptCtx(aes.Aes128).block_length;

const cbc_ctx = struct {
    enc_ctx: aes.AesEncryptCtx(aes.Aes128),
    dec_ctx: aes.AesDecryptCtx(aes.Aes128),
};

pub fn init(key_init: []u8) !cbc_ctx {
    if (key_init != block_length) {
        return error.LengthError;
    }
    const ctx = cbc_ctx{
        aes.Aes128.initEnc(key_init),
        aes.Aes128.initDec(key_init),
    };
    return ctx;
}

// Aes128-CBC BigEndian
pub fn encrypt(dst: []u8, src: []const u8, iv: []const u8) usize {
    debug.assert(dst.len >= src.len);
    const ctx = aes.Aes128.initEnc(key.key);
    var counter: [block_length]u8 = undefined;
    @memcpy(counter[0..block_length], iv[0..block_length]);
    var i: usize = 0;
    // CBC mode
    while (i + block_length <= src.len) : (i += block_length) {
        xor(dst[i .. i + block_length], src[i .. i + block_length], &counter);
        ctx.encrypt(dst[i .. i + block_length][0..block_length], dst[i .. i + block_length][0..block_length]);
        @memcpy(counter[0..block_length], dst[i .. i + block_length][0..block_length]);
    }
    // Pad the message PKCS #7
    if (i < src.len) {
        const pad_length: u8 = @truncate(block_length - (src.len % block_length));
        var pad = [_]u8{pad_length} ** block_length;
        const src_slice = src[i..];
        @memcpy(pad[0..src_slice.len], src_slice);
        xor(&pad, &pad, &counter);
        ctx.encrypt(&pad, &pad);
        @memcpy(dst[i..][0..pad.len], pad[0..block_length]);
    }
    if (src.len % block_length == 0) {
        var pad = [_]u8{block_length} ** block_length;
        const src_slice = src[i..];
        @memcpy(pad[0..src_slice.len], src_slice);
        xor(&pad, &pad, &counter);
        ctx.encrypt(&pad, &pad);
        @memcpy(dst[i..][0..block_length], pad[0..block_length]);
    }
    return i + block_length;
}

pub fn decrypt(dst: []u8, src: []const u8, iv: []const u8) usize {
    debug.assert(dst.len >= src.len);
    const ctx = aes.Aes128.initDec(key.key);
    var counter: [block_length]u8 = undefined;
    @memcpy(counter[0..block_length], iv[0..block_length]);
    var i: usize = 0;
    while (i + block_length <= src.len) : (i += block_length) {
        ctx.decrypt(dst[i .. i + block_length][0..block_length], src[i .. i + block_length][0..block_length]);
        xor(dst[i .. i + block_length], dst[i .. i + block_length], &counter);
        @memcpy(counter[0..block_length], src[i .. i + block_length][0..block_length]);
    }
    if (i < src.len) {
        ctx.decrypt(dst[i..][0..block_length], src[i..][0..block_length]);
        xor(dst[i..][0..block_length], dst[i..][0..block_length], &counter);
    }
    // Check padding
    // Return length of message if ok, otherwise 0.
    const pad_length: u8 = dst[i - 1];
    
    if (pad_length == 0) {
        return 0;
    }

    if (pad_length > block_length) {
        return 0;
    }
    var j: usize = 0;
    while (j < pad_length) : (j += 1) {
        if (dst[i - j - 1] != pad_length) {
            return 0;
        }
    }
    return i - pad_length;
}

fn xor(dst: []u8, src: []const u8, counter: []const u8) void {
    debug.assert(src.len == counter.len);
    debug.assert(dst.len >= src.len);
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        dst[i] = src[i] ^ counter[i];
    }
}

test "xor" {
    const left = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const right = [_]u8{ 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
    const expected = [_]u8{ 0x06, 0x04, 0x06, 0x00, 0x06, 0x04, 0x06 };
    var tst: [7]u8 = undefined;
    xor(&tst, &left, &right);
    try std.testing.expectEqualSlices(u8, expected[0..], tst[0..]);
}

test "encrypt_decrypt" {
    const plaintext = "Banana";
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    var buffer: [16]u8 = undefined;
    var ret = encrypt(&buffer, plaintext, &iv);
    try std.testing.expectEqual(16, ret);
    var decrypted: [16]u8 = undefined;
    ret = decrypt(&decrypted, &buffer, &iv);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..plaintext.len]);
}

test "pad_block_length" {
    const plaintext = "0123456789abcdef";
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    var buffer: [32]u8 = undefined;
    var ret = encrypt(&buffer, plaintext, &iv);
    try std.testing.expectEqual(32, ret);
    var decrypted: [32]u8 = undefined;
    ret = decrypt(&decrypted, &buffer, &iv);
    try std.testing.expectEqual(16, ret);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..ret]);
}

test "padding_0" {
    const plaintext = [_]u8{ 0x00 } ** 16;
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    var buffer: [32]u8 = undefined;
    var ret = encrypt(&buffer, &plaintext, &iv);
    var decrypted: [16]u8 = undefined;
    ret = decrypt(&decrypted, buffer[0..16][0..], &iv);
    try std.testing.expectEqual(0,ret);
}