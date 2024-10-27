const std = @import("std");
const zap = @import("zap");
const cbc = @import("./cbc.zig");

fn on_request(r: zap.Request) void {
    var buffer: [10000]u8 = undefined;
    var ciphertext: [10000]u8 = undefined;
    var plaintext: [10000]u8 = undefined;
    if (r.path) |the_path| {
        const ret = cbc.encrypt(&plaintext, the_path);
        // _ = std.fmt.bufPrint(&plaintext, "{x}", .{plaintext[0..ret]}) catch "0";
        std.debug.print("PATH: {s}, {x}\n", .{ the_path, plaintext[0..ret] });
        // std.debug.print("PATH: {s}\n", .{the_path});
    }

    if (r.query) |the_query| {
        const len: usize = the_query.len / 2;
        _ = parse_hex(&ciphertext, the_query) catch return;
        // _ = std.fmt.bufPrint(&ciphertext, "{x}", .{the_query}) catch return;
        const ret = cbc.decrypt(&buffer, ciphertext[0..len]);
        std.debug.print("Returned decription {s} : {d}\n", .{ buffer[0..len], ret });
        std.debug.print("QUERY: {s}\n", .{the_query});
    }
    r.sendBody("<html><body><h1>Hello</h1></body></html>") catch return;
}

fn parse_hex(dst: []u8, hex_str: []const u8) !void {
    std.debug.assert(dst.len >= hex_str.len / 2);
    const len: usize = hex_str.len;
    var i: usize = 0;
    var j: usize = 0;
    while (i + 2 <= len) : (i += 2) {
        dst[j] = try std.fmt.parseInt(u8, hex_str[i .. i + 2][0..2], 16);
        j += 1;
    }
}

pub fn main() !void {
    // Creates the HTTP listener
    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = on_request,
        .log = true,
    });
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    // Start worker threads
    zap.start(.{
        .threads = 2,
        .workers = 2,
    });

    // // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    // std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // // stdout is for the actual output of your application, for example if you
    // // are implementing gzip, then only the compressed bytes should be sent to
    // // stdout, not any debugging messages.
    // const stdout_file = std.io.getStdOut().writer();
    // var bw = std.io.bufferedWriter(stdout_file);
    // const stdout = bw.writer();

    // try stdout.print("Run `zig build test` to run the tests.\n", .{});

    // try bw.flush(); // don't forget to flush!
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
