const std = @import("std");
const debug = std.debug;
const aes = std.crypto.core.aes;

const block_length = aes.AesDecryptCtx(aes.Aes128).block_length;
const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

// Aes128-CBC BigEndian
pub fn encrypt(dst: []u8, src: []const u8) usize {
    debug.assert(dst.len >= src.len);
    const ctx = aes.Aes128.initEnc(key);
    var counter: [block_length]u8 = undefined;
    @memcpy(counter[0..block_length], iv[0..block_length]);
    var i: usize = 0;
    while (i + block_length <= src.len) : (i += block_length) {
        xor(dst[i .. i + block_length], src[i .. i + block_length], &counter);
        ctx.encrypt(dst[i .. i + block_length][0..block_length], dst[i .. i + block_length][0..block_length]);
        @memcpy(counter[0..block_length], dst[i .. i + block_length][0..block_length]);
    }
    // Pad the message
    if (i < src.len) {
        const pad_length: u8 = @truncate(block_length - (src.len % block_length));
        std.debug.print("Pad length: {d}\n", .{pad_length});
        var pad = [_]u8{pad_length} ** block_length;
        std.debug.print("Pad: {x}\n", .{pad});
        const src_slice = src[i..];
        @memcpy(pad[0..src_slice.len], src_slice);
        std.debug.print("Last block: {x}\n", .{pad});
        xor(&pad, &pad, &counter);
        std.debug.print("Last block xor: {x}\n", .{pad});
        ctx.encrypt(&pad, &pad);
        std.debug.print("Last block enc: {x}\n", .{pad});
        @memcpy(dst[i..][0..pad.len], pad[0..block_length]);
    }
    std.debug.print("{x}\n", .{dst[0 .. i + block_length]});
    return i + block_length;
}

pub fn decrypt(dst: []u8, src: []const u8) usize {
    debug.assert(dst.len >= src.len);
    const ctx = aes.Aes128.initDec(key);
    var counter: [block_length]u8 = undefined;
    @memcpy(counter[0..block_length], iv[0..block_length]);
    var i: usize = 0;
    while (i + block_length <= src.len) : (i += block_length) {
        std.debug.print("i: {d}\n", .{i});
        ctx.decrypt(dst[i .. i + block_length][0..block_length], src[i .. i + block_length][0..block_length]);
        xor(dst[i .. i + block_length], dst[i .. i + block_length], &counter);
        @memcpy(counter[0..block_length], src[i .. i + block_length][0..block_length]);
    }
    if (i < src.len) {
        ctx.decrypt(dst[i..][0..block_length], src[i..][0..block_length]);
        xor(dst[i..][0..block_length], dst[i..][0..block_length], &counter);
    }
    // Check padding
    std.debug.print("Dec: {s}\n", .{dst});
    std.debug.print("i: {d}\n", .{i});
    const pad_length: u8 = dst[i - 1];
    std.debug.print("{x}, {x}\n", .{ dst[i - 2], dst[i - 1] });
    if (pad_length >= block_length) {
        return 1;
    }
    var j: usize = 0;
    while (j < pad_length) : (j += 1) {
        if (dst[i - j - 1] != pad_length) {
            return 1;
        }
    }
    return 0;
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
    var buffer: [16]u8 = undefined;
    var ret = encrypt(&buffer, plaintext);
    try std.testing.expectEqual(16, ret);
    var decrypted: [16]u8 = undefined;
    ret = decrypt(&decrypted, &buffer);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..plaintext.len]);
}
