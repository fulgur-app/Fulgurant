// Entry point bundled by `npm run js:build` into assets/js/age.min.js.
// Exposes the age-encryption library (X25519 recipients) as `window.age`
// so the new-share page can encrypt content in the browser under the
// `script-src 'self'` CSP.
export { Encrypter, Decrypter, generateIdentity, identityToRecipient } from 'age-encryption';
