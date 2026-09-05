# Font assets

`Phosphor-Regular.ttf` is from Phosphor Icons. Its MIT license is retained as
`LICENSE-Phosphor.txt`.

`Phosphor-Subset.ttf` is the checked-in build asset. It contains every
Phosphor codepoint referenced by the UI. Regenerate it whenever an icon glyph
is added or changed:

```sh
pyftsubset assets/fonts/Phosphor-Regular.ttf \
  --output-file=assets/fonts/Phosphor-Subset.ttf \
  --unicodes=U+E136,U+E21E,U+E248,U+E3B4,U+E3D0,U+E3D4,U+E46C,U+E4A6
```

Keep the full `Phosphor-Regular.ttf` as the vendored source; normal Kraken
builds require only the generated subset and do not require FontTools.
