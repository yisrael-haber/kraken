# libyaml source snapshot

Source: `https://github.com/yaml/libyaml`

Release: `0.2.5` (tarball sha256
`fa240dbf262be053f3898006d502d514936c818e422afdcf33921c63bed9bf2e`)

License: MIT (`LICENSE`).

Only the parser is kept: `src/api.c`, `reader.c`, `scanner.c`, `parser.c`,
`yaml_private.h` and `include/yaml.h`, unmodified. The emitter, writer and
document loader are not vendored. `protocols/dcerpc` parses libdcerpc's YAML
replies into Lua tables with the event parser (`yaml_parser_parse`).

The version macros that autotools or CMake would define (`YAML_VERSION_MAJOR`,
`MINOR`, `PATCH`, `STRING`) are set in `build.zig`.
