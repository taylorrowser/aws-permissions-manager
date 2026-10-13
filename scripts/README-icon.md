# App icon

`icon.svg` is the source for `apm/static/icon-512.png`, `icon-192.png` and `apple-touch-icon.png` (180).
This Mac has no SVG rasteriser on the command line, so render it in a browser: open the SVG in a
256x256 CSS-pixel viewport at 2x and screenshot it (512x512), then:

    sips -s format png -z 192 192 icon-512.png --out icon-192.png
    sips -s format png -z 180 180 icon-512.png --out apple-touch-icon.png

The glyph sits inside the centre 84% so the maskable icon survives Android's circle crop.
