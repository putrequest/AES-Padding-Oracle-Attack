const std = @import("std");
const zap = @import("zap");
const cbc = @import("./cbc.zig");

const LengthError = error{
    LengthError,
};

fn onRequest(r: zap.Request) void {
    var ciphertext: [10000]u8 = undefined;
    var buffer: [10000]u8 = undefined;
    var plaintext: [10000]u8 = undefined;
    var iv: [16]u8 = undefined;

    // Pre-prase query parameters
    r.parseQuery();

    // Parse Ciphertext
    if (r.getParamSlice("c")) |value| {
        std.log.info("Ciphertext: {s}", .{value});
        parseFromHex(&ciphertext, value) catch {
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
        if (value.len < iv.len) {
            r.sendBody("IV too short\n") catch return;
            return;
        }
        @memcpy(&iv, value[0..iv.len]);
    } else {
        r.sendBody("No IV provided\n") catch return;
        return;
    }

    // Path encrypt for test purpouse
    if (r.path) |the_path| {
        std.log.info("Encrypting: {s}", .{the_path});
        const ret = cbc.encrypt(&plaintext, the_path, &iv);
        _ = parseToHex(&ciphertext, &plaintext) catch {
            // r.sendBody("Encryption error\n") catch return;
            // return;
        };
        std.debug.print("PATH: {s}, {x}\n", .{ the_path, ciphertext[0..ret] });
    }

    if (r.query) |the_query| {
        const len: usize = the_query.len / 2;
        std.debug.print("Parsing...\n", .{});
        _ = parseFromHex(&ciphertext, the_query) catch return;
        // try parseFromHex(&ciphertext, the_query);
        std.debug.print("Parsed!\n", .{});
        // _ = std.fmt.bufPrint(&ciphertext, "{x}", .{the_query}) catch return;
        const ret = cbc.decrypt(&buffer, ciphertext[0..len], &iv);
        std.debug.print("Returned decription {s} : {d}\n", .{ buffer[0..len], ret });
        std.debug.print("QUERY: {s}\n", .{the_query});
    }
    r.sendBody("<html><body><h1>Hello</h1></body></html>") catch return;
}

fn parseFromHex(dst: []u8, hex_str: []const u8) !void {
    std.debug.assert(dst.len >= hex_str.len / 2);
    if (hex_str.len & 1 == 1) {
        return error.LengthError;
    }
    const len: usize = hex_str.len;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 2 <= len) : (i += 2) {
        std.debug.print("We at {d}\n", .{i});
        dst[j] = try std.fmt.parseInt(u8, hex_str[i .. i + 2][0..2], 16);
        j += 1;
    }
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
        std.debug.print("We at {d}", .{i});
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
