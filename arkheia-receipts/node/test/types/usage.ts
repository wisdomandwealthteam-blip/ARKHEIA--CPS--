// Compile-only check of index.d.ts as SECURUS (TypeScript) would consume it.
import { ReceiptSigner, InMemoryLedger, signingKeyFromSeedHex, buildVerdictPayload, digestJson, verifyReceipt, Keyring, type ArkheiaReceipt } from '../../index.js';
const signer = new ReceiptSigner({ signingKey: signingKeyFromSeedHex('00'.repeat(32)), engineId: 'securus', commitSha: '0'.repeat(40), ledger: new InMemoryLedger() });
async function run(ring: Keyring): Promise<string> {
  const { receipt } = await signer.issue({ wrapperDomain: 'governancecheck', inputDigest: digestJson({}), verdictPayload: buildVerdictPayload({ verdict: 'COMPLIANT', ruleSet: { id: 'securus.posture', version: '1.12.0' } }) });
  const r: ArkheiaReceipt = receipt;
  const v = verifyReceipt(r, ring);
  return v.valid ? v.signer : v.error_code;
}
void run;
