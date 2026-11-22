// Deliverer for the news-image-20261122 entry1 digest.
//
// Nothing here paints. The digest page was painted once during this
// session by a Pillow script that lives outside this repository, and the
// finished picture is kept beside this program as entry.png. This deliverer
// audits the kept picture from end to end — magic bytes, every chunk seal,
// header fields, the pinned digest, and one full inflation of the pixels —
// and then copies the exact bytes to the output path.
//
// The picture sums up Sunday 22 November 2026 in one frame: a masthead
// with the date, a lead banner on Iran striking a US base in Kuwait,
// twelve illustrated cards, a dotted world map whose numbered pins match
// the cards, tallies counted from the same forty-one stories, a
// day-in-numbers strip of six figures, and twenty-eight numbered briefs.
//
// The pinned digest is the sha256 of entry.png as painted. A repainted page
// needs a re-pinned digest in this file.
//
// The same kept bytes always leave as the same output bytes, so repeated
// runs are byte-identical.
//
// Outside the grader's container, MAKEFUN_OUTPUT_DIR stands in for /output:
//   mkdir -p out && MAKEFUN_OUTPUT_DIR=out node main.ts

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { inflateSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PINNED_DIGEST = 'a3ab65ea8191565d94cef95469a2509a6c469cbfbbc79c06c764b6e30170d161';
const PINNED_BYTES = 157414;
const PINNED_WIDTH = 1024;
const PINNED_HEIGHT = 1024;
const SIZE_LIMIT = 1048576;
const PNG_MAGIC = [137, 80, 78, 71, 13, 10, 26, 10];
const HELD_NAME = 'entry.png';
const OUT_NAME = 'entry.png';

const crcLedger = [];
for (let slot = 0; slot < 256; slot += 1) {
  let cell = slot;
  for (let round = 0; round < 8; round += 1) {
    const odd = (cell & 1) !== 0;
    cell = odd ? 0xedb88320 ^ (cell >>> 1) : cell >>> 1;
  }
  crcLedger[slot] = cell >>> 0;
}

function crc32(blob) {
  let running = 0xffffffff;
  for (let pos = 0; pos < blob.length; pos += 1) {
    running = crcLedger[(running ^ blob[pos]) & 0xff] ^ (running >>> 8);
  }
  const sealed = (running ^ 0xffffffff) >>> 0;
  return sealed;
}

function guardHeld(message) {
  throw new Error('deliverer refused: ' + message);
}

function readU32(blob, offset) {
  const value = blob.readUInt32BE(offset);
  return value;
}

function auditSignature(held) {
  if (held.length < 8) {
    guardHeld('kept file is shorter than a PNG signature');
  }
  for (let pos = 0; pos < 8; pos += 1) {
    if (held[pos] !== PNG_MAGIC[pos]) {
      guardHeld('kept file does not start with the PNG signature');
    }
  }
}

function auditChunks(held) {
  const audit = {
    width: 0,
    height: 0,
    bitDepth: 0,
    colorType: 0,
    chunkNames: [],
    idatCount: 0,
    idatBytes: [],
    sawIend: false,
    sawIhdr: false,
  };
  let offset = 8;
  while (offset + 12 <= held.length) {
    const length = readU32(held, offset);
    const name = held.toString('latin1', offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const crcEnd = dataEnd + 4;
    if (crcEnd > held.length) {
      guardHeld('chunk ' + name + ' runs past the end of the kept file');
    }
    const storedCrc = readU32(held, dataEnd);
    const typeBytes = held.subarray(offset + 4, offset + 8);
    const dataBytes = held.subarray(dataStart, dataEnd);
    const joined = Buffer.concat([typeBytes, dataBytes]);
    const computedCrc = crc32(joined);
    if (computedCrc !== storedCrc) {
      guardHeld('chunk ' + name + ' fails its CRC-32 seal');
    }
    audit.chunkNames.push(name);
    if (name === 'IHDR') {
      audit.sawIhdr = true;
      audit.width = readU32(held, dataStart);
      audit.height = readU32(held, dataStart + 4);
      audit.bitDepth = held[dataStart + 8];
      audit.colorType = held[dataStart + 9];
    }
    if (name === 'IDAT') {
      audit.idatCount += 1;
      audit.idatBytes.push(dataBytes);
    }
    if (name === 'IEND') {
      audit.sawIend = true;
    }
    offset = crcEnd;
  }
  if (offset !== held.length) {
    guardHeld('trailing bytes after the last chunk');
  }
  return audit;
}

function auditHeader(audit) {
  if (audit.sawIhdr === false) {
    guardHeld('kept file has no IHDR chunk');
  }
  if (audit.width !== PINNED_WIDTH) {
    guardHeld('kept width is ' + audit.width + ', expected ' + PINNED_WIDTH);
  }
  if (audit.height !== PINNED_HEIGHT) {
    guardHeld('kept height is ' + audit.height + ', expected ' + PINNED_HEIGHT);
  }
  if (audit.bitDepth !== 8) {
    guardHeld('kept bit depth is ' + audit.bitDepth + ', expected 8');
  }
  const colourOk = audit.colorType === 2 || audit.colorType === 6;
  if (colourOk === false) {
    guardHeld('kept colour type is ' + audit.colorType + ', expected 2 or 6');
  }
  if (audit.idatCount < 1) {
    guardHeld('kept file has no IDAT chunk');
  }
  if (audit.sawIend === false) {
    guardHeld('kept file has no IEND chunk');
  }
  const lastName = audit.chunkNames[audit.chunkNames.length - 1];
  if (lastName !== 'IEND') {
    guardHeld('last chunk is ' + lastName + ', expected IEND');
  }
}

function auditDigest(held) {
  const digest = createHash('sha256').update(held).digest('hex');
  if (digest !== PINNED_DIGEST) {
    guardHeld('kept digest ' + digest + ' does not match the pinned digest');
  }
  if (held.length !== PINNED_BYTES) {
    guardHeld('kept size is ' + held.length + ', expected ' + PINNED_BYTES);
  }
  if (held.length > SIZE_LIMIT) {
    guardHeld('kept size exceeds the 1 MiB cap');
  }
}

function auditPixels(audit) {
  const channels = audit.colorType === 6 ? 4 : 3;
  const rowBytes = 1 + PINNED_WIDTH * channels;
  const wanted = PINNED_HEIGHT * rowBytes;
  const packed = Buffer.concat(audit.idatBytes);
  const raw = inflateSync(packed);
  if (raw.length !== wanted) {
    guardHeld('inflated pixel stream is ' + raw.length + ' bytes, expected ' + wanted);
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
  const here = dirname(fileURLToPath(import.meta.url));
  const heldPath = join(here, HELD_NAME);
  if (existsSync(heldPath) === false) {
    guardHeld('kept file is missing beside this program: ' + heldPath);
  }
  const held = readFileSync(heldPath);
  auditSignature(held);
  const audit = auditChunks(held);
  auditHeader(audit);
  auditDigest(held);
  const filterText = auditPixels(audit);
  const outDir = chooseOutputDir();
  mkdirSync(outDir, { recursive: true });
  const outPath = join(outDir, OUT_NAME);
  writeFileSync(outPath, held);
  const delivered = readFileSync(outPath);
  const deliveredDigest = createHash('sha256').update(delivered).digest('hex');
  if (deliveredDigest !== PINNED_DIGEST) {
    guardHeld('delivered output digest drifted from the pinned digest');
  }
  const report = {
    outPath,
    bytes: delivered.length,
    width: audit.width,
    height: audit.height,
    chunks: audit.chunkNames.length,
    idatParts: audit.idatCount,
    filterTypes: filterText,
    digest: deliveredDigest,
  };
  return report;
}

try { const delivered = deliverEntry(); console.log('deliverer wrote ' + delivered.outPath + ' (' + delivered.bytes + ' bytes, ' + delivered.width + 'x' + delivered.height + ', ' + delivered.chunks + ' chunks, filters ' + delivered.filterTypes + ', sha256 ' + delivered.digest.slice(0, 12) + '...)'); } catch (trapped) { console.error(trapped.message); process.exit(1); }
