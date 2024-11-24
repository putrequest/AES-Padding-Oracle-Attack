const std = @import("std");
const zap = @import("zap");
const cbc = @import("./cbc.zig");

const LengthError = error{
    LengthError,
};

const Decryption = struct {
    ciphertext: []const u8,
    iv: []const u8,
};

const Handler = struct {
    var alloc: std.mem.Allocator = undefined;

    pub fn onRequest(r: zap.Request) void {
        if (r.body) |body| {
            const maybe_dec: ?std.json.Parsed(Decryption) = std.json.parseFromSlice(Decryption, Handler.alloc, body, .{}) catch null;
            if (maybe_dec) |dec| {
                defer dec.deinit();
                std.log.info("Dec `{any}`, iv `{any}`", .{ dec.value.ciphertext, dec.value.iv });

                // Parse ciphertext
                const cipher = Handler.alloc.alloc(u8, dec.value.ciphertext.len / 2) catch undefined;
                defer Handler.alloc.free(cipher);
                _ = parseFromHex(cipher, dec.value.ciphertext) catch {
                    r.sendBody("Invalid ciphertext\n") catch return;
                    return;
                };

                // Parse IV
                var iv: [16]u8 = undefined;
                if (dec.value.iv.len / 2 != 16) {
                    r.sendBody("IV too short\n") catch return;
                    return;
                }
                _ = parseFromHex(&iv, dec.value.iv) catch {
                    r.sendBody("Invalid IV\n") catch return;
                    return;
                };
                // Decrypt
                var buff = Handler.alloc.alloc(u8, cipher.len) catch undefined;
                defer Handler.alloc.free(buff);
                const ret = cbc.decrypt(buff, cipher, &iv);
                if (ret == 0) {
                    r.sendBody("Decryption error\n") catch return;
                    return;
                }
                std.log.info("Decrypted: {s}", .{buff[0..ret]});
            } else {
                r.sendBody("Invalid data\n") catch return;
                return;
            }
        } else {
            r.sendBody("Invalid body\n") catch return;
            return;
        }

        r.sendBody("All good!\n") catch return;
    }
};

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
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};
    const allocator = gpa.allocator();

    Handler.alloc = allocator;

    // Creates the HTTP listener
    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = Handler.onRequest,
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
