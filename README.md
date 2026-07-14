# curve25519-ts

Fork de `curve25519-js` (Harvey Connor, basado en axlsign.js/TweetNaCl) renombrado como `curve25519-ts`.

API pública sin cambios: `generateKeyPair(seed)`, `sharedKey(secretKey, publicKey)`, `sign(secretKey, msg, opt_random?)`, `verify(publicKey, msg, signature)`, `signMessage`, `openMessage`.

## Cambios respecto al original

- **`sharedKey()` rechaza claves públicas de orden bajo.** Si el resultado del intercambio Diffie-Hellman (X25519) es todo-cero (lo que ocurre con la clave pública `0x00...00` u otros puntos de orden bajo conocidos), ahora lanza `Error('invalid public key (low-order point)')` en vez de devolver un secreto compartido predecible en silencio.
- **`curve25519_sign()` limpia de memoria la clave Ed25519 derivada** (`edsk`) inmediatamente después de firmar, en vez de dejarla en el buffer indefinidamente.
- **`checkArrayTypes()` corregido**: usaba el objeto `arguments` en vez de sus propios parámetros rest declarados; ahora valida los argumentos que realmente recibe.
- Se eliminó el `export default {}` (no tenía propósito y podía confundir a quien hiciera `import curve25519 from 'curve25519-ts'`).
- `package.json` ahora declara `"types": "lib/index.d.ts"` para que los consumidores TypeScript reciban los tipos generados por `tsc` automáticamente.
- **`openMessage()` ya no muta el `signedMsg` que le pasas.** Antes reenviaba el array del caller directo a `curve25519_sign_open`, que le limpiaba el bit alto del último byte; una segunda verificación del mismo buffer fallaba con `null` aunque la firma fuera válida. Ahora trabaja sobre una copia.
- **`tsconfig.json` declara `rootDir: "./src"` explícito.** Sin esto, algunos compiladores de TypeScript emiten en `lib/src/index.js` en vez de `lib/index.js`, rompiendo el `main`/`types` de `package.json`.
- **`package.json` agrega el script `prepare`**, que corre el build automáticamente al instalar el paquete como dependencia de git o antes de `npm publish`, para no volver a publicar/consumir el paquete sin `lib/`/`lib-esm/` compilados.
- **Limpieza de memoria extendida a todos los buffers intermedios con material de clave.** `crypto_scalarmult()` limpia el escalar clampeado (`z`) tras el intercambio; `crypto_sign_direct()` y `crypto_sign_direct_rnd()` limpian el nonce derivado (`r`), el hash intermedio (`h`) y el acumulador (`x`) tras firmar.
- **Tipado explícito en toda la librería.** Se eliminó `any` de todas las firmas internas y públicas a favor de `Uint8Array`, `Float64Array`/`GF` y `Point` (`[GF, GF, GF, GF]`), con `export interface KeyPair`.
- **Migrado de `tslint` (deprecado) a ESLint** (`@typescript-eslint` + `eslint-config-prettier`).
- **TypeScript actualizado a `^5.4.5`** (antes `^3.5.3`).
- **Build dual CommonJS + ESM.** `npm run build` genera `lib/` (CJS) y `lib-esm/` (ESM); `package.json` declara `exports` map con `require`/`import`/`types`.
- **`package.json` declara `files: ["lib", "lib-esm"]`** para controlar explícitamente qué se publica, en vez de depender solo de `.npmignore`.
- Código fuente sin comentarios.

## Build

```
npm install
npm run build
```

Genera `lib/` (CommonJS) y `lib-esm/` (ES Modules).

## Lint / Format

```
npm run lint
npm run format
```
