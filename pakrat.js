#!/usr/bin/env node
require('dotenv').config();
const axios = require('axios');
const { runSandbox } = require('./sandbox');
const fs = require('fs');

async function getPackageInfo(name) {
  const url = `https://registry.npmjs.org/${name}/latest`;
  const res = await axios.get(url);
  return {
    name,
    version: res.data.version,
    dependencies: res.data.dependencies || {},
    scripts: res.data.scripts || {},
    hasInstallScript: !!(res.data.scripts?.postinstall || res.data.scripts?.preinstall || res.data.scripts?.install)
  };
}

async function scanPackage(name) {
  console.log(`\npakrat scanning ${name}...\n`);

  let info;
  try {
    info = await getPackageInfo(name);
  } catch (err) {
    console.log(`[ERROR] could not fetch ${name} from npm: ${err.message}`);
    process.exit(1);
  }

  console.log(`package:     ${info.name}`);
  console.log(`version:     ${info.version}`);
  console.log(`deps:        ${Object.keys(info.dependencies).length}`);
  console.log(`dep list:    ${Object.keys(info.dependencies).join(', ') || 'none'}`);
  console.log(`install script: ${info.hasInstallScript ? '⚠️  YES' : 'no'}`);

  if (info.hasInstallScript) {
    console.log(`scripts:     ${JSON.stringify(info.scripts)}`);
  }

  console.log(`\nrunning sandbox...\n`);
  const result = runSandbox(name, info.version);

  if (result.suspiciousActivity.length > 0) {
    console.log(`🚨 SUSPICIOUS ACTIVITY DETECTED:`);
    result.suspiciousActivity.forEach(a => console.log(`  ⚠️  ${a}`));
    if (result.networkCalls.length > 0) {
      console.log(`\nunexpected DNS lookups:`);
      result.networkCalls.forEach(c => console.log(`  → ${c}`));
    }
  } else {
    console.log(`✅ sandbox clean - no suspicious activity`);
  }

  if (result.error) {
    console.log(`\nsandbox error: ${result.error}`);
  }

  console.log(`\ninstall output:`);
  console.log(result.installOutput);
}

const command = process.argv[2];
const target = process.argv[3];

if (command === 'scan' && target) {
  scanPackage(target);
} else {
  console.log(`
pakrat - npm supply chain monitor

usage:
  node pakrat.js scan <package>    scan a specific package
  node index.js                    run full baseline check

examples:
  node pakrat.js scan axios
  node pakrat.js scan lodash
  node pakrat.js scan express
  `);
}
