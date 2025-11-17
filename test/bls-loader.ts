/**
 * Loader for @noble/curves BLS12-381
 * This library is ESM but works better with CommonJS via dynamic import
 */

let blsModule: any = null;

export async function getBls(): Promise<any> {
  if (blsModule === null) {
    // @noble/curves is ESM, use dynamic import
    const imported = await import("@noble/curves/bls12-381");
    blsModule = imported.bls12_381;
  }
  return blsModule;
}
