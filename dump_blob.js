'use strict';
const wire = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x05,0x01,0x01,0x66,0x00,0x00,
  0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b,
]);
const mod = new WebAssembly.Module(wire);
const blob = new Uint8Array(d8.wasm.serializeModule(mod));
print('blob size:', blob.length);
const dv = new DataView(blob.buffer);

// Dump all header fields
print('[0]  magic           = 0x' + dv.getUint32(0,true).toString(16));
print('[4]  version_hash    = 0x' + dv.getUint32(4,true).toString(16));
print('[8]  cpu_features    = 0x' + dv.getUint32(8,true).toString(16));
print('[12] flags_hash      = 0x' + dv.getUint32(12,true).toString(16));
print('[16] enabled_feat    = 0x' + dv.getUint32(16,true).toString(16));
print('[20] import_flags    = 0x' + dv.getUint32(20,true).toString(16));
print('[24] const_mod_len   = 0x' + dv.getUint32(24,true).toString(16));
print('[28] detected_feat   = 0x' + dv.getBigUint64(28,true).toString(16));
print('[36] total_code_size = ' + dv.getBigUint64(36,true));
print('[44] tier_marker     = 0x' + blob[44].toString(16));
for (let i = 0; i < 10; i++) {
  print('[' + (45 + i*4) + '] field' + i + ' = ' + dv.getInt32(45 + i*4, true));
}
print('[85] after 10 fields: 0x' + blob[85].toString(16));

// full hex dump
let out = '\nFull hex dump:';
for (let i = 0; i < blob.length; i++) {
  if (i % 16 === 0) out += '\n' + String(i).padStart(4,' ') + ': ';
  out += blob[i].toString(16).padStart(2,'0') + ' ';
}
print(out);
