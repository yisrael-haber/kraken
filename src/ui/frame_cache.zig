const std = @import("std");
const c = @import("c");

/// Keeps the last drawn UI in a texture, so a frame whose render commands did not change costs
/// one textured quad instead of a software rasterisation of the whole window.
pub const FrameCache = struct {
    images: [2]c.sg_image = @splat(.{}), // colour, depth
    views: [3]c.sg_view = @splat(.{}), // colour target, depth target, colour texture
    size: [2]i32 = .{ 0, 0 },
    hash: u64 = 0,

    pub fn present(self: *FrameCache, commands: c.Clay_RenderCommandArray, fonts: [*c]c.sclay_font_t) void {
        const size = [2]i32{ c.sapp_width(), c.sapp_height() };
        const resized = !std.mem.eql(i32, &size, &self.size);
        if (resized) self.resize(size);
        const hash = hashCommands(commands);
        if (resized or hash != self.hash) {
            self.hash = hash;
            var pass: c.sg_pass = .{};
            pass.attachments.colors[0] = self.views[0];
            pass.attachments.depth_stencil = self.views[1];
            c.sg_begin_pass(&pass);
            c.sgl_matrix_mode_modelview();
            c.sgl_load_identity();
            c.sclay_render(commands, fonts);
            c.sgl_draw();
            c.sg_end_pass();
        }
        c.sg_begin_pass(&.{ .swapchain = c.sglue_swapchain() });
        c.sgl_defaults();
        c.sgl_enable_texture();
        c.sgl_texture(self.views[2], .{});
        // A render target's top row is v = 1 in GL and v = 0 where the origin is top-left.
        const top: f32 = if (c.sg_query_features().origin_top_left) 0 else 1;
        c.sgl_begin_triangle_strip();
        for ([_][4]f32{ .{ -1, -1, 0, 1 - top }, .{ 1, -1, 1, 1 - top }, .{ -1, 1, 0, top }, .{ 1, 1, 1, top } }) |v| {
            c.sgl_v2f_t2f(v[0], v[1], v[2], v[3]);
        }
        c.sgl_end();
        c.sgl_draw();
        c.sg_end_pass();
    }

    fn resize(self: *FrameCache, size: [2]i32) void {
        for (self.views) |view| c.sg_destroy_view(view);
        for (self.images) |image| c.sg_destroy_image(image);
        const defaults = c.sglue_environment().defaults;
        self.size = size;
        self.images[0] = c.sg_make_image(&.{ .usage = .{ .color_attachment = true }, .width = size[0], .height = size[1], .pixel_format = defaults.color_format });
        self.images[1] = c.sg_make_image(&.{ .usage = .{ .depth_stencil_attachment = true }, .width = size[0], .height = size[1], .pixel_format = defaults.depth_format });
        self.views[0] = c.sg_make_view(&.{ .color_attachment = .{ .image = self.images[0] } });
        self.views[1] = c.sg_make_view(&.{ .depth_stencil_attachment = .{ .image = self.images[1] } });
        self.views[2] = c.sg_make_view(&.{ .texture = .{ .image = self.images[0] } });
    }
};

/// Hashes what the renderer reads. Text goes by content because Clay reuses its buffers; a
/// false difference only costs a redraw, so padding bytes are not a correctness issue.
fn hashCommands(commands: c.Clay_RenderCommandArray) u64 {
    var hash: std.hash.Wyhash = .init(0);
    for (commands.internalArray[0..@intCast(commands.length)]) |*command| {
        hash.update(std.mem.asBytes(&command.commandType));
        hash.update(std.mem.asBytes(&command.boundingBox));
        switch (command.commandType) {
            c.CLAY_RENDER_COMMAND_TYPE_RECTANGLE => hash.update(std.mem.asBytes(&command.renderData.rectangle)),
            c.CLAY_RENDER_COMMAND_TYPE_BORDER => inline for (.{ "color", "cornerRadius", "width" }) |field| {
                hash.update(std.mem.asBytes(&@field(command.renderData.border, field)));
            },
            c.CLAY_RENDER_COMMAND_TYPE_TEXT => {
                const text = &command.renderData.text;
                hash.update(std.mem.asBytes(&text.textColor));
                hash.update(std.mem.asBytes(&text.fontSize));
                hash.update(text.stringContents.chars[0..@intCast(text.stringContents.length)]);
            },
            else => {},
        }
    }
    return hash.final();
}
