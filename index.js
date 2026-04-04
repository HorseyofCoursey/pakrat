require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const { execSync } = require('child_process');
const { runSandbox } = require('./sandbox');
const { runEbpfSandbox } = require('./ebpf-monitor');

async function sendDiscordAlert(message) {
  try {
    await axios.post(process.env.DISCORD_WEBHOOK, {
      content: message
    });
  } catch (err) {
    console.log(`Discord alert failed: ${err.message}`);
  }
}

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

async function getTopPackages() {
  return [
    'lodash', 'express', 'react', 'axios', 'chalk',
    'commander', 'typescript', 'webpack', 'babel-core', 'eslint',
    'moment', 'underscore', 'jquery', 'vue', 'angular',
    'next', 'nuxt', 'gatsby', 'prisma', 'mongoose',
    'dotenv', 'cors', 'helmet', 'morgan', 'nodemon',
    'jest', 'mocha', 'chai', 'supertest', 'sinon',
    'prettier', 'husky', 'lint-staged', 'rollup', 'vite',
    'tailwindcss', 'postcss', 'autoprefixer', 'sass', 'less',
    'socket.io', 'ws', 'uuid', 'bcrypt', 'jsonwebtoken',
    'multer', 'sharp', 'cheerio', 'puppeteer', 'playwright'
  ];
}

function diffPackage(old, current) {
  const alerts = [];

  if (old.version !== current.version) {
    alerts.push(`📦 NEW VERSION: ${old.version} → ${current.version}`);
  }

  const oldDeps = Object.keys(old.dependencies);
  const newDeps = Object.keys(current.dependencies);

  const added = newDeps.filter(d => !oldDeps.includes(d));
  const removed = oldDeps.filter(d => !newDeps.includes(d));

  if (added.length > 0) {
    alerts.push(`⚠️ DEPS ADDED: ${added.join(', ')}`);
  }
  if (removed.length > 0) {
    alerts.push(`📉 DEPS REMOVED: ${removed.join(', ')}`);
  }

  if (!old.hasInstallScript && current.hasInstallScript) {
    alerts.push(`🚨 INSTALL SCRIPT ADDED - HIGH RISK`);
  }

  return alerts;
}

async function updateScanLog(results) {
  try {
    const logPath = '/root/pakrat/scan-log.json';
    const log = JSON.parse(fs.readFileSync(logPath));

    log.scans.unshift({
      timestamp: new Date().toISOString(),
      packages: results.map(r => ({
        name: r.name,
        version: r.version,
        depCount: Object.keys(r.dependencies).length,
        hasInstallScript: r.hasInstallScript
      }))
    });

    // Keep only last 100 scans
    log.scans = log.scans.slice(0, 100);

    fs.writeFileSync(logPath, JSON.stringify(log, null, 2));

    execSync(
      `cd /root/pakrat && git add scan-log.json && git commit -m "scan ${new Date().toISOString()}" && git push`,
      { stdio: 'ignore' }
    );

  } catch (err) {
    console.log(`scan log update failed: ${err.message}`);
  }
}

async function run() {
  const timestamp = new Date().toISOString();
  const baselineExists = fs.existsSync('baseline.json');
  const baseline = baselineExists
    ? JSON.parse(fs.readFileSync('baseline.json'))
    : [];

  console.log(`pakrat scanning... ${timestamp}\n`);

  const PACKAGES = await getTopPackages();
  console.log(`watching ${PACKAGES.length} packages\n`);

  const results = [];
  let anyAlerts = false;
  const alertMessages = [];

  for (const pkg of PACKAGES) {
    try {
      const current = await getPackageInfo(pkg);
      results.push(current);

      const old = baseline.find(b => b.name === pkg);

      if (!old) {
        console.log(`[NEW] ${pkg}@${current.version} - no baseline yet`);
        continue;
      }

      const alerts = diffPackage(old, current);

      if (alerts.length > 0) {
        anyAlerts = true;
        console.log(`[ALERT] ${pkg}`);
        alerts.forEach(a => {
          console.log(`  ${a}`);
          alertMessages.push(`**${pkg}**: ${a}`);
        });

        // Run tcpdump sandbox
        console.log(`  [sandbox] running network analysis...`);
        const sandboxResult = runSandbox(pkg, current.version);

        if (sandboxResult.suspiciousActivity.length > 0) {
          sandboxResult.suspiciousActivity.forEach(a => {
            console.log(`  🔬 SANDBOX: ${a}`);
            alertMessages.push(`**${pkg}**: 🔬 SANDBOX: ${a}`);
          });
        } else {
          console.log(`  [sandbox] nothing suspicious at install time`);
        }

        // Run eBPF kernel monitor
        console.log(`  [ebpf] running kernel analysis...`);
        const ebpfResult = runEbpfSandbox(pkg, current.version);

        if (ebpfResult.suspiciousActivity.length > 0) {
          ebpfResult.suspiciousActivity.forEach(a => {
            console.log(`  🔬 EBPF: ${a}`);
            alertMessages.push(`**${pkg}**: 🔬 EBPF: ${a}`);
          });
        } else {
          console.log(`  [ebpf] nothing suspicious at kernel level`);
        }

      } else {
        console.log(`[OK] ${pkg}@${current.version}`);
      }

    } catch (err) {
      console.log(`[ERROR] ${pkg}: ${err.message}`);
    }
  }

  fs.writeFileSync('baseline.json', JSON.stringify(results, null, 2));

  if (anyAlerts) {
    const message = `🚨 **PAKRAT ALERT** - ${timestamp}\n\n${alertMessages.join('\n')}`;
    await sendDiscordAlert(message);
    console.log('\n⚠️  ALERTS FOUND - Discord notified');
  } else {
    console.log('\n✅ All packages look clean');
  }

  await updateScanLog(results);
}

run();
