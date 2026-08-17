# Clay source snapshot

Source: `https://github.com/nicbarker/clay`

Commit: `e6cc36941ab2af5d81107617039d6f527a1c660b`

Kept files: `clay.h` and the Sokol renderer used by Kraken.

Local change: `clay.h` treats `/` and `\` as optional line-wrap points when
the text measurement callback has non-null user data. The separator remains
part of the measured word.
