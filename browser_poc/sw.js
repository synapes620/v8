// Service Worker: 첫 요청 → 200-fn Wasm, 이후 → 1-fn Wasm
// poc.html에서 postMessage로 mode 전환

let mode = '200fn';

self.addEventListener('message', e => { mode = e.data.mode; });

// wire bytes 미리 생성
function leb128(n) {
  const r=[];
  do { let b=n&0x7f; n>>>=7; r.push(n?b|0x80:b); } while(n);
  return new Uint8Array(r);
}

function build200fn() {
  const N=200;
  const typeSec=new Uint8Array([0x01,0x05,0x01,0x60,0x00,0x01,0x7f]);
  const fnIdxs=new Uint8Array(N); // all 0x00
  const fnLeb=leb128(N);
  const fnPayload=new Uint8Array(fnLeb.length+N);
  fnPayload.set(fnLeb); fnPayload.set(fnIdxs,fnLeb.length);
  const funcSec=new Uint8Array([0x03,...leb128(fnPayload.length),...fnPayload]);
  const body=new Uint8Array([0x04,0x00,0x41,0x00,0x0b]);
  const codeBuf=[];
  for(let i=0;i<N;i++) codeBuf.push(...body);
  const codePayload=new Uint8Array([...leb128(N),...codeBuf]);
  const codeSec=new Uint8Array([0x0a,...leb128(codePayload.length),...codePayload]);
  return new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
                         ...typeSec,...funcSec,...codeSec]);
}

const wire1fn = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,
  0x0a,0x06,0x01,0x04,0x00,0x41,0x2a,0x0b
]);
const wire200fn = build200fn();

self.addEventListener('fetch', e => {
  if (!e.request.url.endsWith('/module.wasm')) return;
  const bytes = (mode === '200fn') ? wire200fn : wire1fn;
  console.log(`[SW] Serving ${mode}: ${bytes.length}B`);
  e.respondWith(new Response(bytes, {
    headers: {
      'Content-Type': 'application/wasm',
      'Cache-Control': 'no-store'
    }
  }));
});
