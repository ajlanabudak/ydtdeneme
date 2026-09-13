/* YDT Deneme — Service Worker
   Amaç: zayıf/askıda kalan hücresel bağlantıda uygulamanın AÇILMAMASINI önlemek.
   Strateji: uygulama kabuğu için önbellek öncelikli (cache-first) + arka planda
   sessiz güncelleme. Ağ asla açılışı bekletmez. */
const CACHE = 'ydt-deneme-v4';
const SHELL = 'ydt-deneme-pwa.html';
const ASSETS = [SHELL,'manifest.json','rba-logo.png','icon-192.png','icon-512.png'];
const AG_ZAMAN_ASIMI = 4000;   // ms — bu süreyi geçen ağ isteği bırakılır

self.addEventListener('install', e=>{
  e.waitUntil(
    caches.open(CACHE)
      // allSettled: eksik bir ikon yüzünden tüm kurulum başarısız olmasın
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

/* Ağ isteğini zaman aşımıyla dener; süre dolarsa reddeder. */
function agZamanAsimiyla(req){
  return new Promise((coz, red)=>{
    const zaman = setTimeout(()=>red(new Error('timeout')), AG_ZAMAN_ASIMI);
    fetch(req).then(r=>{clearTimeout(zaman);coz(r)}).catch(err=>{clearTimeout(zaman);red(err)});
  });
}

self.addEventListener('fetch', e=>{
  const req = e.request;
  if(req.method !== 'GET') return;                       // sonuç POST'ları dokunulmaz
  const url = new URL(req.url);
  if(url.origin !== location.origin) return;             // Supabase/Pusula doğrudan ağa

  // Sayfa gezinmesi: her koşulda kabuğu önbellekten ver.
  if(req.mode === 'navigate'){
    e.respondWith(
      caches.match(SHELL).then(hit=>{
        if(hit){
          // arka planda sessizce tazele, kullanıcı beklemez
          e.waitUntil(agZamanAsimiyla(new Request(SHELL,{cache:'reload'}))
            .then(r=>r && r.ok && caches.open(CACHE).then(c=>c.put(SHELL,r.clone())))
            .catch(()=>{}));
          return hit;
        }
        return agZamanAsimiyla(req).then(r=>{
          const kopya=r.clone();
          caches.open(CACHE).then(c=>c.put(SHELL,kopya)).catch(()=>{});
          return r;
        });
      })
    );
    return;
  }

  // Diğer yerel varlıklar: önbellek öncelikli, yoksa zaman aşımlı ağ.
  e.respondWith(
    caches.match(req).then(hit=>{
      if(hit) return hit;
      return agZamanAsimiyla(req).then(r=>{
        if(r && r.ok){
          const kopya=r.clone();
          caches.open(CACHE).then(c=>c.put(req,kopya)).catch(()=>{});
        }
        return r;
      }).catch(()=>caches.match(SHELL));
    })
  );
});
