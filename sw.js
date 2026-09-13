/* YDT Deneme — Service Worker (KAPATMA SÜRÜMÜ)
   Amaç: Telefonlarda saplanıp kalan eski/bozuk Service Worker'ları
   kendi kendini kaldırarak temizlemek. Bu sürüm hiçbir şeyi
   önbelleğe almaz, hiçbir isteği yakalamaz — yalnızca kendini siler
   ve açık sekmeleri bir kez yeniler. */

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', async () => {
  try {
    // varsa önbellekleri temizle
    const isimler = await caches.keys();
    await Promise.all(isimler.map(k => caches.delete(k)));
  } catch (e) {}

  // kendini kaldır
  await self.registration.unregister();

  // acik sekmeleri normal (SW'siz) modda yenile
  const istemciler = await self.clients.matchAll({ type: 'window' });
  istemciler.forEach(c => c.navigate(c.url));
});
