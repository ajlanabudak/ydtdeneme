/* ═══════════════════════════════════════════════════════════════
   YDT Deneme — KVKK Kripto Modülü
   Royal British Academy · KeyKampüs Kurs Merkezi

   AMAÇ: Öğrencinin adı ve soyadı hiçbir koşulda düz metin olarak
   bulut veritabanına ulaşmaz. Öğrenci cihazında kurumun AÇIK
   anahtarıyla şifrelenir; yalnızca öğretmenin cihazındaki ÖZEL
   anahtarla çözülebilir. Özel anahtar sunucuya hiç yüklenmez.

   MİMARİ: Hibrit şifreleme (Web Crypto API, tarayıcı yerleşik)
     1) Rastgele AES-256-GCM oturum anahtarı üretilir
     2) Kimlik bilgisi bu anahtarla şifrelenir
     3) Oturum anahtarı RSA-OAEP-2048 ile kurum açık anahtarına sarılır
     4) Sunucuya yalnızca üç şifreli parça gönderilir

   TAKMA KİMLİK: Aynı öğrencinin iki kez deneme çözmesini engellemek
   için ada ihtiyaç var, fakat adın kendisine değil. Ad-soyad, kuruma
   özel bir tuzla HMAC-SHA256'dan geçirilir; sunucuda yalnızca bu
   geri döndürülemez özet durur.

   YASAL NOT: Takma kimlik, KVKK anlamında hâlâ kişisel veridir
   (anonim değil, pseudonimdir). Bu modül riski azaltır, veri
   sorumlusunun yükümlülüklerini ortadan kaldırmaz.
   ═══════════════════════════════════════════════════════════════ */

window.YDT_KVKK = (function(){
"use strict";

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ── yardımcılar ── */
function b64(buf){
  const b = new Uint8Array(buf); let s = "";
  for(let i=0;i<b.length;i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function unb64(str){
  const s = atob(str), b = new Uint8Array(s.length);
  for(let i=0;i<s.length;i++) b[i] = s.charCodeAt(i);
  return b;
}
function destekVar(){
  return !!(window.crypto && window.crypto.subtle && window.crypto.getRandomValues);
}

/* ── ad-soyad normalizasyonu (takma kimlik tutarlılığı için) ──
   "Ali  YILMAZ" ve "ali yılmaz" aynı özeti üretmeli. */
function normalizeAd(ad, soyad){
  return (String(ad||"") + " " + String(soyad||""))
    .toLocaleLowerCase("tr")
    .replace(/\s+/g," ")
    .trim();
}

/* ── TAKMA KİMLİK ──
   HMAC-SHA256(normalize(ad soyad), kurum_tuzu) → 32 haneli hex.
   Tuz istemci tarafında gömülü olduğu için bu bir gizlilik değil,
   geri döndürülemezlik önlemidir: sunucudaki değerden ada dönülemez,
   fakat ad bilinen bir kişi için özet yeniden hesaplanabilir. */
async function takmaKimlik(ad, soyad, tuz){
  if(!destekVar()) throw new Error("Tarayıcı Web Crypto desteklemiyor");
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(String(tuz)),
    {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(normalizeAd(ad,soyad)));
  return [...new Uint8Array(sig)].slice(0,16)
    .map(x=>x.toString(16).padStart(2,"0")).join("");
}

/* ══════════════════════════════════════════════════════════
   PEM / BASE64 ANAHTAR DESTEĞİ
   Mevcut uygulamalarda anahtarlar PKCS#8 (özel) ve SPKI (açık)
   base64 biçiminde tutuluyorsa doğrudan kullanılabilsin diye.
   "MIIEvwIBADANBgkqhkiG9w0BAQEF..." → PKCS#8 özel anahtar
   "MIIBIjANBgkqhkiG9w0BAQEF..."     → SPKI açık anahtar
   ══════════════════════════════════════════════════════════ */
function pemTemizle(metin){
  return String(metin||"")
    .replace(/-----BEGIN [^-]+-----/g,"")
    .replace(/-----END [^-]+-----/g,"")
    .replace(/\s+/g,"");
}
/** PKCS#8 base64 özel anahtarı içe alır. hash: "SHA-256" (varsayılan) veya "SHA-1" */
async function ozelAnahtarPem(metin, hash){
  const ham = unb64(pemTemizle(metin));
  return crypto.subtle.importKey("pkcs8", ham,
    {name:"RSA-OAEP", hash: hash || "SHA-256"}, true, ["decrypt"]);
}
/** SPKI base64 açık anahtarı içe alır. */
async function acikAnahtarPem(metin, hash){
  const ham = unb64(pemTemizle(metin));
  return crypto.subtle.importKey("spki", ham,
    {name:"RSA-OAEP", hash: hash || "SHA-256"}, true, ["encrypt"]);
}
/** Özel anahtardan eşleşen AÇIK anahtarı türetir (JWK olarak döner).
    Öğrenci uygulamasına yapıştırılacak blok bununla üretilir. */
async function acikAnahtariTuret(ozelPemVeyaJwk, hash){
  const ozel = typeof ozelPemVeyaJwk === "string"
    ? await ozelAnahtarPem(ozelPemVeyaJwk, hash)
    : await crypto.subtle.importKey("jwk", ozelPemVeyaJwk,
        {name:"RSA-OAEP", hash: hash||"SHA-256"}, true, ["decrypt"]);
  const jwk = await crypto.subtle.exportKey("jwk", ozel);
  // özel bileşenleri at → geriye açık anahtar kalır
  ["d","p","q","dp","dq","qi","oth"].forEach(k=>delete jwk[k]);
  jwk.key_ops = ["encrypt"];
  delete jwk.ext;
  return jwk;
}
/** Anahtar metnini tanır: 'pkcs8' | 'spki' | 'jwk' | 'bilinmiyor' */
function anahtarTuru(metin){
  const t = String(metin||"").trim();
  if(t.startsWith("{")) { try{ const j=JSON.parse(t); return j.d ? "jwk-ozel" : "jwk-acik"; }catch(e){ return "bilinmiyor" } }
  const b = pemTemizle(t);
  if(/^MIIE|^MIIJ|^MIG2/.test(b)) return "pkcs8";     // özel anahtar
  if(/^MIIB|^MFww|^MIGf/.test(b)) return "spki";      // açık anahtar
  return "bilinmiyor";
}

/* ── ANAHTAR ÇİFTİ ÜRETİMİ (yalnızca anahtar üretme aracında) ── */
async function anahtarCiftiUret(){
  const pair = await crypto.subtle.generateKey(
    {name:"RSA-OAEP", modulusLength:2048,
     publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256"},
    true, ["encrypt","decrypt"]);
  const acik  = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const ozel  = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return {acik, ozel};
}

/* ══════════════════════════════════════════════════════════
   PAROLA MODU (simetrik)
   Mevcut uygulamalarda tek parça uzun bir anahtar kullanılıyorsa
   bu mod uyumluluk için vardır.

   UYARI: Simetrik modda şifreyi çözen anahtar, öğrenci
   uygulamasının içinde de bulunur. Veritabanına erişebilen ve
   uygulama kaynağını okuyabilen biri adları çözebilir. Bu mod
   RSA modundan ZAYIFTIR; aydınlatma metninde "anahtar yalnızca
   öğretmende" denemez. Yeni kurulumlarda RSA modu kullanılmalıdır.
   ══════════════════════════════════════════════════════════ */
async function parolaAnahtari(parola, tuz){
  const ham = await crypto.subtle.importKey("raw", enc.encode(String(parola)),
    {name:"PBKDF2"}, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name:"PBKDF2", salt:enc.encode(String(tuz||"ydt-kvkk")), iterations:150000, hash:"SHA-256"},
    ham, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
async function kimlikSifreleParola(kimlikObj, parola, tuz){
  const k = await parolaAnahtari(parola, tuz);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt({name:"AES-GCM", iv}, k,
    enc.encode(JSON.stringify(kimlikObj)));
  return "P1." + b64(iv) + "." + b64(c);          // P1 = parola modu işareti
}
async function kimlikCozParola(paket, parola, tuz){
  const p = String(paket||"").split(".");
  if(p[0] !== "P1" || p.length !== 3) throw new Error("Parola modu paketi değil");
  const k = await parolaAnahtari(parola, tuz);
  const acik = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(p[1])}, k, unb64(p[2]));
  return JSON.parse(dec.decode(acik));
}

/* Paket hangi modda üretilmiş? */
function paketModu(paket){
  return String(paket||"").startsWith("P1.") ? "parola" : "rsa";
}

/* ── ŞİFRELEME (öğrenci uygulaması) ── */
async function acikAnahtarYukle(jwk){
  return crypto.subtle.importKey("jwk", jwk,
    {name:"RSA-OAEP", hash:"SHA-256"}, false, ["encrypt"]);
}

/**
 * Kimlik bilgisini şifreler.
 * @returns {string} "sarilmisAnahtar.iv.sifreliMetin" (base64, noktayla ayrık)
 */
async function kimlikSifrele(kimlikObj, acikAnahtarJwk){
  if(!destekVar()) throw new Error("Tarayıcı Web Crypto desteklemiyor");
  const rsa = await acikAnahtarYukle(acikAnahtarJwk);
  const aes = await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt"]);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const sifreli = await crypto.subtle.encrypt({name:"AES-GCM", iv}, aes,
    enc.encode(JSON.stringify(kimlikObj)));
  const aesRaw  = await crypto.subtle.exportKey("raw", aes);
  const sarilmis= await crypto.subtle.encrypt({name:"RSA-OAEP"}, rsa, aesRaw);
  return b64(sarilmis) + "." + b64(iv) + "." + b64(sifreli);
}

/* ── ÇÖZME (öğretmen paneli) ── */
async function ozelAnahtarYukle(jwk){
  return crypto.subtle.importKey("jwk", jwk,
    {name:"RSA-OAEP", hash:"SHA-256"}, false, ["decrypt"]);
}

async function kimlikCoz(paket, ozelAnahtar){
  const parca = String(paket||"").split(".");
  if(parca.length !== 3) throw new Error("Şifreli kimlik biçimi geçersiz");
  const aesRaw = await crypto.subtle.decrypt({name:"RSA-OAEP"}, ozelAnahtar, unb64(parca[0]));
  const aes = await crypto.subtle.importKey("raw", aesRaw, {name:"AES-GCM"}, false, ["decrypt"]);
  const acik = await crypto.subtle.decrypt(
    {name:"AES-GCM", iv:unb64(parca[1])}, aes, unb64(parca[2]));
  return JSON.parse(dec.decode(acik));
}

/* ── AYDINLATMA METNİ (KVKK m.10) ──
   Öğrenci sınava başlamadan önce görür. Metin uygulamanın gerçekte
   ne yaptığını anlatır; genel bir şablon değildir. */
const AYDINLATMA = {
  surum: "1.0",
  tarih: "2026",
  baslik: "Kişisel Verilerin Korunması Hakkında Bilgilendirme",
  kurum: "Royal British Academy · KeyKampüs Kurs Merkezi",
  metin: [
    ["Hangi verileriniz işleniyor?",
     "Adınız ve soyadınız, çözdüğünüz deneme numarası, her soruya verdiğiniz cevap, "+
     "cevaplarınızı değiştirme sayınız, soru başına geçirdiğiniz süre ve hesaplanan net puanınız."],
    ["Adınız nasıl korunuyor?",
     "Adınız ve soyadınız bu cihazda, kurumun açık anahtarıyla şifrelenir ve sunucuya yalnızca "+
     "şifreli hâliyle gönderilir. Şifreyi çözebilecek özel anahtar yalnızca öğretmeninizin "+
     "cihazında bulunur ve sunucuya hiç yüklenmez. Sunucuda adınızın düz hâli hiçbir zaman yer almaz."],
    ["Neden işleniyor?",
     "Kayıt olduğunuz kurs hizmetinin yürütülmesi için: sınav sonucunuzun hesaplanması, "+
     "eksik olduğunuz becerilerin belirlenmesi ve öğretmeninizin size uygun çalışma programı "+
     "hazırlaması amacıyla. Hukuki dayanak, KVKK m.5/2-c uyarınca eğitim sözleşmesinin ifasıdır."],
    ["Kimler görebiliyor?",
     "Yalnızca kurumdaki yetkili öğretmeniniz ve kurum yönetimi. Sonuçlarınız başka "+
     "öğrencilerle paylaşılmaz, üçüncü kişilere satılmaz, reklam amacıyla kullanılmaz."],
    ["Ne kadar süre saklanıyor?",
     "Sınav kayıtlarınız, kurs kaydınızın sona ermesinden itibaren en çok bir eğitim yılı "+
     "boyunca saklanır, ardından silinir. Bu süreden önce silinmesini talep edebilirsiniz."],
    ["Haklarınız neler?",
     "Verilerinizin işlenip işlenmediğini öğrenme, bir kopyasını isteme, yanlışsa düzeltilmesini "+
     "ve silinmesini isteme hakkınız vardır (KVKK m.11). Bu talepleri kurum sekreterliğine "+
     "veya öğretmeninize iletmeniz yeterlidir; talebiniz en geç 30 gün içinde yanıtlanır."],
    ["18 yaşından küçükseniz",
     "Kurs kaydınız sırasında veliniz tarafından imzalanan bilgilendirme ve onay formu bu "+
     "uygulamayı da kapsar. Veliniz aynı hakları sizin adına kullanabilir."]
  ],
  ozet: "Adın bu cihazda şifrelenir, sunucuya düz hâliyle hiç gitmez. "+
        "Sonuçlarını yalnızca öğretmenin görür. Silinmesini istediğinde silinir."
};

return {
  destekVar, normalizeAd, takmaKimlik,
  anahtarCiftiUret, kimlikSifrele, ozelAnahtarYukle, kimlikCoz,
  kimlikSifreleParola, kimlikCozParola, paketModu,
  ozelAnahtarPem, acikAnahtarPem, acikAnahtariTuret, anahtarTuru, pemTemizle,
  AYDINLATMA, _b64:b64, _unb64:unb64
};
})();
