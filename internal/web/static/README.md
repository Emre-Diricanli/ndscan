# Frontend assets

`index.html` (authored on the feat/web-ui branch) is embedded into the binary
by internal/web/frontend.go. This file exists so the embed pattern always has
a matching file even before the frontend lands — `go:embed` fails to compile on
an empty directory, and it ignores dotfiles like .gitkeep.
