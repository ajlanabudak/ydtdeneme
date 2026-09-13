/* YDT Deneme — Service Worker (v5)
   Royal British Academy · KeyKampüs Kurs Merkezi

   v4'teki hata: her sayfa isteğine öğrenci uygulaması döndürülüyordu; kök
   adres ve öğretmen paneli yanlış dosyayı alıyor, önbellek boşsa istek
   ERR_FAILED ile düşüyordu. v5 her adresi kendi dosyasıyla eşler ve her
   durumda bir yedeği vardır. */

const CACHE = 'ydt-deneme-v5';
const GIRIS  = 'index.html';
const ASSETS = [
  'index.html',
  'ydt-deneme-pwa.html',
  'ydt-ogretmen.html',
  'kvkk.js',
  'manifest.json',
  'rba-logo.png',
  'rba-arma.png',
  'icon-192.png',
  'icon-512.png'
];
const ZAMAN_ASIMI = 6000;

self.addEventListener('install', e=>{
  e.waitUntil(
    caches.open(CACHE)
      // allSettled: eksik tek bir dosya tüm kurulumu düşürmesin
      .then(c=>Promise.allSettled(ASSETS.map(a=>c.add(new Request(a,{cache:'reload'})))))
      .then(()=>self.skipWaiting())
  );
});

self.addEventListener('activate', e=>{
  e.waitUntil(
    caches.keys()
      .then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
  );
});

function agZamanAsimiyla(req, ms){
  return new Promise((coz, red)=>{
    const t = setTimeout(()=>red(new Error('timeout')), ms || ZAMAN_ASIMI);
    fetch(req).then(r=>{clearTimeout(t);coz(r)}).catch(e=>{clearTimeout(t);red(e)});
  });
}

self.addEventListener('fetch', e=>{
  const req = e.request;
  if(req.method !== 'GET') return;                    // sonuç gönderimleri dokunulmaz
  const url = new URL(req.url);
  if(url.origin !== location.origin) return;          // Supabase doğrudan ağa gider

  // Kök adres "/" → index.html
  let anahtar = req;
  if(url.pathname === '/' || url.pathname === '') {
    anahtar = new Request(new URL(GIRIS, location.origin).href, {cache:'reload'});
  }

  e.respondWith((async ()=>{
    const c = await caches.open(CACHE);

    // 1) Önbellekte varsa hemen ver, arka planda sessizce tazele
    const hit = await c.match(anahtar, {ignoreSearch:true});
    if(hit){
      e.waitUntil(
        agZamanAsimiyla(new Request(anahtar.url, {cache:'reload'}))
          .then(r=>{ if(r && r.ok) return c.put(anahtar, r.clone()); })
          .catch(()=>{})
      );
      return hit;
    }

    // 2) Yoksa ağdan al ve önbelleğe koy
    try{
      const r = await agZamanAsimiyla(anahtar);
      if(r && r.ok) c.put(anahtar, r.clone()).catch(()=>{});
      return r;
    }catch(err){
      // 3) Ağ da yoksa: sayfa isteğiyse giriş sayfasını ver, o da yoksa açıklayıcı yanıt
      if(req.mode === 'navigate'){
        const giris = await c.match(GIRIS) || await c.match('index.html');
        if(giris) return giris;
        return new Response(
          '<!doctype html><meta charset="utf-8"><title>Bağlantı yok</title>'+
          '<body style="font-family:system-ui;background:#F7F3EA;color:#2A0E4F;padding:40px;text-align:center">'+
          '<h2>Bağlantı kurulamadı</h2><p>İnternete bağlanıp sayfayı yenileyin.</p></body>',
          {headers:{'Content-Type':'text/html; charset=utf-8'}, status:503}
        );
      }
      return Response.error();
    }
  })());
});
