#!/usr/bin/env node
/**
 * Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.
 */

import { existsSync } from 'node:fs';
import { dirname, join, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));

function printUsage() {
  console.log(`
Usage:
  node run_conformance.mjs [options]

Options:
  --adapter <path>    Path to validator adapter module (default: ./adapter.example.mjs)
  --demo-weak         Run conformance test against intentionally-weak demo validator
  --help, -h          Show this help message
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    process.exit(0);
  }

  const isDemoWeak = args.includes('--demo-weak');

  let adapterPath;
  const adapterIdx = args.indexOf('--adapter');

  if (isDemoWeak) {
    adapterPath = join(SCRIPT_DIR, 'reference', 'weak-validator.mjs');
  } else if (adapterIdx !== -1 && args[adapterIdx + 1]) {
    const rawPath = args[adapterIdx + 1];
    if (isAbsolute(rawPath)) {
      adapterPath = rawPath;
    } else {
      const fromCwd = resolve(process.cwd(), rawPath);
      const fromScript = resolve(SCRIPT_DIR, rawPath);
      adapterPath = existsSync(fromCwd) ? fromCwd : (existsSync(fromScript) ? fromScript : fromCwd);
    }
  } else {
    adapterPath = join(SCRIPT_DIR, 'adapter.example.mjs');
  }

  console.log('='.repeat(105));
  console.log('AGENT-PAYMENTS MANDATE CONFORMANCE KIT');
  console.log('Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.');
  console.log('Model 05 / Results R13: 6 Controls across Formal Properties P10, P11, P12');
  console.log('='.repeat(105));

  if (isDemoWeak) {
    console.log('\n[DEMO MODE] this is the intentionally-weak demo validator');
    console.log('Loaded: reference/weak-validator.mjs');
    console.log('This validator intentionally skips payee_check and revocation_check to demonstrate gap detection.\n');
  } else {
    console.log(`\nAdapter loaded: ${adapterPath}\n`);
  }

  // Load adapter module
  let adapterModule;
  try {
    const adapterUrl = pathToFileURL(adapterPath).href;
    adapterModule = await import(adapterUrl);
  } catch (err) {
    console.error(`Error loading adapter from '${adapterPath}':`, err.message);
    process.exit(2);
  }

  const decide = adapterModule.decide || adapterModule.validatePayment;
  if (typeof decide !== 'function') {
    console.error(`Error: Adapter at '${adapterPath}' must export a 'decide' or 'validatePayment' function.`);
    process.exit(2);
  }

  // Load test vectors
  const vectorsUrl = pathToFileURL(join(SCRIPT_DIR, 'vectors.mjs')).href;
  const { vectors } = await import(vectorsUrl);

  const colControl = 19;
  const colProp = 6;
  const colAttack = 46;
  const colExpect = 8;
  const colGot = 8;
  const colResult = 8;

  const header = [
    'Control'.padEnd(colControl),
    'Prop'.padEnd(colProp),
    'Attack / Scenario'.padEnd(colAttack),
    'Expect'.padEnd(colExpect),
    'Got'.padEnd(colGot),
    'Result'.padEnd(colResult)
  ].join(' | ');

  console.log('-'.repeat(header.length));
  console.log(header);
  console.log('-'.repeat(header.length));

  let passCount = 0;
  let failCount = 0;
  const failedControls = [];

  for (const vec of vectors) {
    let result;
    try {
      result = await decide({
        mandate: vec.mandate,
        request: vec.request,
        deps: vec.deps
      });
    } catch (err) {
      result = { allow: false, reason: `EXCEPTION: ${err.message}` };
    }

    const got = result?.allow ? 'allow' : 'deny';
    const isPass = (got === vec.expect);

    if (isPass) {
      passCount++;
    } else {
      failCount++;
      if (!failedControls.includes(vec.control)) {
        failedControls.push(vec.control);
      }
    }

    // Format attack/scenario note to fit column cleanly
    let noteText = vec.note;
    if (noteText.length > colAttack) {
      noteText = noteText.substring(0, colAttack - 3) + '...';
    }

    const row = [
      vec.control.padEnd(colControl),
      vec.property.split(',')[0].trim().padEnd(colProp),
      noteText.padEnd(colAttack),
      vec.expect.padEnd(colExpect),
      got.padEnd(colGot),
      (isPass ? 'PASS' : 'FAIL').padEnd(colResult)
    ].join(' | ');

    console.log(row);
  }

  console.log('-'.repeat(header.length));
  console.log(`\nSummary: ${passCount} passed, ${failCount} failed (out of ${vectors.length} vectors)`);

  if (isDemoWeak) {
    console.log(`Expected demonstration failures detected in controls: ${failedControls.join(', ')}`);
    console.log('Confirmation: this is the intentionally-weak demo validator correctly caught by the test suite.');
  }

  // Print Defense Map Footer
  console.log('\n' + '='.repeat(105));
  console.log('DEFENSE MAP (Model 05 / Results R13 -> Formal Properties -> RFC Standards)');
  console.log('='.repeat(105));
  console.log([
    'Control'.padEnd(19),
    'Property'.padEnd(9),
    'Attack Mitigated'.padEnd(28),
    'Guard Enforced'.padEnd(20),
    'Standard Clause'
  ].join(' | '));
  console.log('-'.repeat(105));
  console.log([
    'consent_binding'.padEnd(19),
    'P10'.padEnd(9),
    'Consent substitution'.padEnd(28),
    'approved_by_user'.padEnd(20),
    'RFC 9396 §2 / draft-mishra §9.1'
  ].join(' | '));
  console.log([
    'payee_check'.padEnd(19),
    'P10'.padEnd(9),
    'Payee redirection'.padEnd(28),
    'payee exact match'.padEnd(20),
    'RFC 9396 §2.2'
  ].join(' | '));
  console.log([
    'amount_cap_check'.padEnd(19),
    'P10'.padEnd(9),
    'Over-debit beyond cap'.padEnd(28),
    'amount <= cap'.padEnd(20),
    'RFC 9396 §2.2'
  ].join(' | '));
  console.log([
    'audience_check'.padEnd(19),
    'P10'.padEnd(9),
    'Cross-server token replay'.padEnd(28),
    'aud === server'.padEnd(20),
    'RFC 8707 §3 / RFC 7519 §4.1.3'
  ].join(' | '));
  console.log([
    'sender_constraint'.padEnd(19),
    'P12'.padEnd(9),
    'Bearer request replay'.padEnd(28),
    'DPoP PoP (cnf key)'.padEnd(20),
    'RFC 9449 §5 / draft-mishra §6'
  ].join(' | '));
  console.log([
    'revocation_check'.padEnd(19),
    'P11'.padEnd(9),
    'Post-revocation debit'.padEnd(28),
    'Online lookup'.padEnd(20),
    'RFC 7009 / draft-mishra §7'
  ].join(' | '));
  console.log('='.repeat(105) + '\n');

  if (isDemoWeak) {
    // Demonstration mode must exit non-zero (showing payee + revocation FAIL)
    process.exit(1);
  } else {
    process.exit(failCount === 0 ? 0 : 1);
  }
}

main().catch((err) => {
  console.error('Fatal conformance test error:', err);
  process.exit(2);
});
