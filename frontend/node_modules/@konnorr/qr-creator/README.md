> This is a fork of <https://github.com/nimiq/qr-creator>

## Why fork?

The original library hasn't seen any updates in 6 years, and all the PRs have languished for anywhere from 2-4years with no comments.

In <https://github.com/shoelace-style/webawesome/> we have a funky workaround to work with SSR:

<https://github.com/shoelace-style/webawesome/blob/9df0572e1f09318fe0475564265166f5d0cfe105/packages/webawesome/src/components/qr-code/qr-code.ts#L72-L79>

This is needed because of this line:

<https://github.com/nimiq/qr-creator/blob/2ee3528ca26344d1891c642fad99160e0e57245b/src/qr-creator.js#L12>

In addition, there was also a feature request for images in the center (i can't find the issue now) and wanted to integrate that for Web Awesome as well.

I also wanted to add jsdoc comments for better autocomplete experience + type checking.

## `@konnorr/qr-creator`

<img src="https://konnorrogers.github.io/qr-creator/demo/qr-code-example.png"/>

A lightweight library generating stylish QR codes that also support gradient fills, rounded corners, different colored corners, and logos in only ~13kB minified (~5kB gzipped).
Try out the [demo](https://konnorrogers.github.io/qr-creator/)!

## Origin

This library is a trimmed down version of [Lars Jung's jQuery.qrcode library](https://larsjung.de/jquery-qrcode/). Our library is however not based on jQuery anymore and doesnt make use of it. Lars Jung's library itself is based on this [QR code Generator](https://github.com/kazuhikoarase/qrcode-generator).

All parts are licensed under the MIT License.

## Installation

To install via npm:
```bash
npm install --save @konnorr/qr-creator
```
To install via yarn:
```bash
yarn add @konnorr/qr-creator
```
Or use a cdn like [jsdelivr](http://www.jsdelivr.com/package/npm/@konnorr/qr-creator) or
[unpkg](https://unpkg.com/browse/@konnorr/qr-creator@2.0.0/) (see [usage](#usage)).

## Usage

The library is available as an ES Module.
To import it as a module:

```javascript
  // from installed package for bundling with a module bundler like webpack:
  import QrCreator from '@konnorr/qr-creator';
  // from cdn:
  import QrCreator from 'https://cdn.jsdelivr.net/npm/@konnorr/qr-creator';
```

Call the QrCreator API with a configuration object and a DOM element or canvas to render the QR code into:

```javascript
  QrCreator.render({
    text: 'some text',
    radius: 0.5, // 0.0 to 0.5
    ecLevel: 'H', // L, M, Q, H
    fill: '#536DFE', // foreground color
    background: null, // color or null for transparent
    size: 128 // in pixels
  }, document.querySelector('#qr-code'));
```

Attribute | Options | Default | Description
----------|---------|---------|------------
text | String | "" | Any kind of text, also links, email addresses, any thing. The library will figure out the size of the QR code to fit all the text inside.
radius | 0 .. 0.5 | 0.5 | Defines how round the blocks should be. Numbers from 0 (squares) to 0.5 (maximum round) are supported.
ecLevel | L, M, Q, H | L | Means "Error correction levels". The four values L, M, Q, and H will use %7, 15%, 25%, and 30% of the QR code for error correction respectively. So on one hand the code will get bigger but chances are also higher that it will be read without errors later on.
fill | color or gradient | #000000 | What color you want your QR code to be. Use the demo to try different colors.
cornerFill | color or gradient | #000000 | What color you want the 3 corners of your QR code to be. Use the demo to try different colors.
background | color code | null | The background color or null for transparent background.
size | int | 200 | The total size of the final QR code in pixels - it will be a square.
image | string | null | The image (url or data uri) you want to display inside your QR code
imageEcCover | 0-1 | 0.5 | How much of the center of the QR code should be covered by the image. The closer you get to 1, the more likely errors will occur in your QR code making it harder to scan.
imageBackground | color or gradient | "transparent" | The background of your image. Useful if your image is transparent and you don't want pieces of the QR code bleeding into your image.
context | CanvasRenderingContext2D | null | Allows passing a rendering context. This is useful if you plan to use the same rendering to grab an SVG. An example can be found in the demo how this works.

If you want to fill the QR code with a gradient, use the following format:
```js
{
    type: 'radial-gradient', // or 'linear-gradient'
    position: [ ... ],
    colorStops: [
        [ offset0, color0 ],
        [ offset1, color1 ],
        ...
    ]
}
```
Where the position is specified as in [createLinearGradient](https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/createLinearGradient) / [createRadialGradient](https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/createRadialGradient). However, each value is relative to the QR code size, i.e. will be multiplied by that size to yield the absolute position.

## Trimmed down to be low weight
The goal of the library is to generate QR codes only. For that reason we have removed all additional code such as GIF image generation, background image support, rendering a label on top, removed some dead code, and freed it from depending on jQuery. Also, the resulting library does not use any global variables, is all strict mode, and relies on modern browser standards instead.

## Building

To install the dependencies run:
```bash
npm install
```
and then to build the project:
```bash
npm run build
```

## Acknowledgements

- @Nimick for the original library this was forked from: <https://github.com/nimiq/qr-creator>
- @Tomas-M https://github.com/nimiq/qr-creator/pull/17
- @WickyNilliams https://github.com/nimiq/qr-creator/pull/11
- @andrin-n-dream https://github.com/nimiq/qr-creator/pull/10

The above PRs were integrated or modified in some way.
