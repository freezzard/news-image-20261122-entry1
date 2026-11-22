// Courier for the news-image-20261122 entry1 digest.
//
// Nothing here paints a pixel. The digest page was painted once during
// this session by a Pillow script that lives outside this repository, and
// the finished picture is kept beside this program as entry.png. This
// courier audits the kept picture from end to end — magic bytes, every
// chunk seal, header fields, the pinned digest, and one full inflation of
// the pixel stream — and then copies the exact bytes to the output path.
//
// The picture is a one-frame summary of the twenty-second of November,
// twenty twenty-six: a masthead carrying the date, a lead banner on the
// Gulf strikes, a dozen illustrated cards, a dotted world map whose
// numbered pins match the cards, tallies counted from the same forty-one
// stories, a six-figure day-in-numbers strip, and twenty-eight numbered
// briefs.
//
// The pinned digest is the sha256 of entry.png as painted. A repainted page
// needs a re-pinned digest in this file.
//
// The same kept bytes always leave as the same output bytes, so repeated
// runs are byte-identical.
//
// Outside the grader's container, MAKEFUN_OUTPUT_DIR stands in for /output:
//   mkdir -p out && MAKEFUN_OUTPUT_DIR=out node main.ts

import { createHash as hashMaker } from 'node:crypto';
import { existsSync as pathExists, mkdirSync as makeDir, readFileSync as readBytes, writeFileSync as writeBytes } from 'node:fs';
import { inflateSync as inflate } from 'node:zlib';
import { dirname as dirOf, join as joinPath } from 'node:path';
import { fileURLToPath as urlToPath } from 'node:url';

const PINNED_DIGEST = 'a3ab65ea8191565d94cef95469a2509a6c469cbfbbc79c06c764b6e30170d161';
const PINNED_BYTES = 157414;
const PINNED_WIDTH = 1024;
const PINNED_HEIGHT = 1024;
const SIZE_LIMIT = 1048576;
const PNG_MAGIC = [137, 80, 78, 71, 13, 10, 26, 10];
const HELD_NAME = 'entry.png';
const OUT_NAME = 'entry.png';

const crcLedger = [];
for (let n = 0; n < 256; n++) {
  let v = n;
  for (let k = 0; k < 8; k++) {
    v = (v & 1) ? (0xedb88320 ^ (v >>> 1)) : (v >>> 1);
  }
  crcLedger[n] = v >>> 0;
}

function crc32(blob) {
  let acc = 0xffffffff;
  for (let i = 0; i < blob.length; i++) {
    acc = crcLedger[(acc ^ blob[i]) & 0xff] ^ (acc >>> 8);
  }
  const sealed = (acc ^ 0xffffffff) >>> 0;
  return sealed;
}

function guardKept(message) {
  throw new Error('courier refused: ' + message);
}

function readU32(blob, offset) {
  const value = blob.readUInt32BE(offset);
  return value;
}

function auditSignature(held) {
  const short = held.length < 8;
  if (short) {
    guardKept('kept file is shorter than a PNG signature');
  }
  for (let i = 0; i < PNG_MAGIC.length; i++) {
    if (held[i] !== PNG_MAGIC[i]) {
      guardKept('kept file does not start with the PNG signature');
    }
  }
}

function auditChunks(held) {
  const audit = {
    picWidth: 0,
    picHeight: 0,
    depthBits: 0,
    colourKind: 0,
    names: [],
    idatSeen: 0,
    idatChunks: [],
    gotIend: false,
    gotIhdr: false,
  };
  let offset = 8;
  while (offset + 12 <= held.length) {
    const length = readU32(held, offset);
    const name = held.toString('latin1', offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const crcEnd = dataEnd + 4;
    if (crcEnd > held.length) {
      guardKept('chunk ' + name + ' runs past the end of the kept file');
    }
    const storedCrc = readU32(held, dataEnd);
    const typeBytes = held.subarray(offset + 4, offset + 8);
    const dataBytes = held.subarray(dataStart, dataEnd);
    const joined = Buffer.concat([typeBytes, dataBytes]);
    const computedCrc = crc32(joined);
    if (computedCrc !== storedCrc) {
      guardKept('chunk ' + name + ' fails its CRC-32 seal');
    }
    audit.names.push(name);
    if (name === 'IHDR') {
      audit.gotIhdr = true;
      audit.picWidth = readU32(held, dataStart);
      audit.picHeight = readU32(held, dataStart + 4);
      audit.depthBits = held[dataStart + 8];
      audit.colourKind = held[dataStart + 9];
    }
    if (name === 'IDAT') {
      audit.idatSeen += 1;
      audit.idatChunks.push(dataBytes);
    }
    if (name === 'IEND') {
      audit.gotIend = true;
    }
    offset = crcEnd;
  }
  if (offset !== held.length) {
    guardKept('trailing bytes after the last chunk');
  }
  return audit;
}

function auditHeader(audit) {
  if (audit.gotIhdr === false) {
    guardKept('kept file has no IHDR chunk');
  }
  if (audit.picWidth !== PINNED_WIDTH) {
    guardKept('kept width is ' + audit.picWidth + ', expected ' + PINNED_WIDTH);
  }
  if (audit.picHeight !== PINNED_HEIGHT) {
    guardKept('kept height is ' + audit.picHeight + ', expected ' + PINNED_HEIGHT);
  }
  if (audit.depthBits !== 8) {
    guardKept('kept bit depth is ' + audit.depthBits + ', expected 8');
  }
  const colourOk = audit.colourKind === 2 || audit.colourKind === 6;
  if (colourOk === false) {
    guardKept('kept colour type is ' + audit.colourKind + ', expected 2 or 6');
  }
  if (audit.idatSeen < 1) {
    guardKept('kept file has no IDAT chunk');
  }
  if (audit.gotIend === false) {
    guardKept('kept file has no IEND chunk');
  }
  const lastName = audit.names[audit.names.length - 1];
  if (lastName !== 'IEND') {
    guardKept('last chunk is ' + lastName + ', expected IEND');
  }
}

function auditDigest(held) {
  const digest = hashMaker('sha256').update(held).digest('hex');
  if (digest !== PINNED_DIGEST) {
    guardKept('kept digest ' + digest + ' does not match the pinned digest');
  }
  if (held.length !== PINNED_BYTES) {
    guardKept('kept size is ' + held.length + ', expected ' + PINNED_BYTES);
  }
  if (held.length > SIZE_LIMIT) {
    guardKept('kept size exceeds the 1 MiB cap');
  }
}

function auditPixels(audit) {
  const channels = audit.colourKind === 6 ? 4 : 3;
  const rowBytes = 1 + PINNED_WIDTH * channels;
  const wanted = PINNED_HEIGHT * rowBytes;
  const packed = Buffer.concat(audit.idatChunks);
  const raw = inflate(packed);
  if (raw.length !== wanted) {
    guardKept('inflated pixel stream is ' + raw.length + ' bytes, expected ' + wanted);
  }
  const filterSeen = new Set();
  for (let row = 0; row < PINNED_HEIGHT; row += 1) {
    filterSeen.add(raw[row * rowBytes]);
  }
  const filterList = [...filterSeen].sort();
  const filterText = filterList.join(',');
  return filterText;
}

function chooseOutputDir() {
  const override = process.env.MAKEFUN_OUTPUT_DIR;
  const picked = override !== undefined && override !== '' ? override : '/output';
  return picked;
}

function deliverEntry() {
  const here = dirOf(urlToPath(import.meta.url));
  const heldPath = joinPath(here, HELD_NAME);
  if (pathExists(heldPath) === false) {
    guardKept('kept file is missing beside this program: ' + heldPath);
  }
  const held = readBytes(heldPath);
  auditSignature(held);
  const audit = auditChunks(held);
  auditHeader(audit);
  auditDigest(held);
  const filterText = auditPixels(audit);
  const outDir = chooseOutputDir();
  makeDir(outDir, { recursive: true });
  const outPath = joinPath(outDir, OUT_NAME);
  writeBytes(outPath, held);
  const delivered = readBytes(outPath);
  const deliveredDigest = hashMaker('sha256').update(delivered).digest('hex');
  if (deliveredDigest !== PINNED_DIGEST) {
    guardKept('delivered output digest drifted from the pinned digest');
  }
  const report = {
    outPath,
    bytes: delivered.length,
    width: audit.picWidth,
    height: audit.picHeight,
    chunks: audit.names.length,
    idatParts: audit.idatSeen,
    filterTypes: filterText,
    digest: deliveredDigest,
  };
  return report;
}

try { const delivered = deliverEntry(); console.log('courier wrote ' + delivered.outPath + ' (' + delivered.bytes + ' bytes, ' + delivered.width + 'x' + delivered.height + ', ' + delivered.chunks + ' chunks, filters ' + delivered.filterTypes + ', sha256 ' + delivered.digest.slice(0, 12) + '...)'); } catch (trapped) { console.error(trapped.message); process.exit(1); }
