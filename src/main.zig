const std = @import("std");
const zap = @import("zap");
const cbc = @import("./cbc.zig");

const LengthError = error{
    LengthError,
};

fn onRequest(r: zap.Request) void {
    var ciphertext: [10000]u8 = undefined;
    var buffer: [10000]u8 = undefined;
    // var plaintext: [10000]u8 = undefined;
    var len: usize = 0;
    var iv: [16]u8 = undefined;

    // Pre-prase query parameters
    r.parseQuery();

    // Parse Ciphertext
    if (r.getParamSlice("c")) |value| {
        std.log.info("Ciphertext: {s}", .{value});
        len = parseFromHex(&ciphertext, value) catch {
            r.sendBody("Invalid ciphertext\n") catch return;
            return;
        };
    } else {
        r.sendBody("No ciphertext provided\n") catch return;
        return;
    }

    // Parse IV
    if (r.getParamSlice("iv")) |value| {
        std.log.info("Param iv: {s}", .{value});
        const value_len = value.len / 2;
        if (value_len != iv.len) {
            r.sendBody("IV too short\n") catch return;
            return;
        }
        _ = parseFromHex(&iv, value) catch {
            r.sendBody("Invalid IV\n") catch return;
            return;
        };
    } else {
        r.sendBody("No IV provided\n") catch return;
        return;
    }

    // Path encrypt for test purpouse
    // if (r.path) |the_path| {
    //     std.log.info("Encrypting: {s}", .{the_path});
    //     const ret = cbc.encrypt(&plaintext, the_path, &iv);
    //     _ = parseToHex(&ciphertext, &plaintext) catch {
    //         r.sendBody("Encryption error\n") catch return;
    //         return;
    //     };
    //     std.debug.print("PATH: {s}, {x}\n", .{ the_path, ciphertext[0..ret] });
    // }

    if (r.query) |_| {
        const ciphertext_slice = ciphertext[0..][0..len];
        const ret = cbc.decrypt(&buffer, ciphertext_slice, &iv);
        if (ret == 0) {
            r.sendBody("Decryption error\n") catch return;
            return;
        }
        std.log.info("Decrypted: {s}", .{buffer[0..ret]});
    }
    r.sendBody("All good!\n") catch return;
}

fn parseFromHex(dst: []u8, hex_str: []const u8) !usize {
    std.debug.assert(dst.len >= hex_str.len / 2);
    if (hex_str.len & 1 == 1) {
        return error.LengthError;
    }
    const len: usize = hex_str.len;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 2 <= len) : (i += 2) {
        dst[j] = try std.fmt.parseInt(u8, hex_str[i .. i + 2][0..2], 16);
        j += 1;
    }
    return i / 2;
}

fn parseToHex(dst: []u8, str: []const u8) !void {
    if (dst.len < str.len * 2) {
        return error.LengthError;
    }
    const len: usize = str.len * 2;
    var buffer: [2]u8 = undefined;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 2 <= len) : (i += 2) {
        _ = try std.fmt.bufPrint(&buffer, "{x}", .{str[j]});
        @memcpy(dst[i .. i + 1], &buffer);
        j += 1;
    }
}

pub fn main() !void {
    // Creates the HTTP listener
    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = onRequest,
        .log = true,
    });
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    // Start worker threads
    zap.start(.{
        .threads = 2,
        .workers = 2,
    });
}
