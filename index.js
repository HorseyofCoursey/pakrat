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
    // HTTP clients
    'axios', 'got', 'node-fetch', 'superagent', 'undici', 'ky',

    // Core utilities
    'lodash', 'underscore', 'ramda', 'date-fns', 'moment', 'dayjs',
    'uuid', 'nanoid', 'shortid', 'cuid',

    // Environment and config
    'dotenv', 'cross-env', 'config', 'convict', 'env-var',

    // CLI tools
    'commander', 'yargs', 'meow', 'minimist', 'chalk', 'ora',
    'inquirer', 'prompts', 'kleur', 'picocolors',

    // Build tools
    'webpack', 'rollup', 'vite', 'esbuild', 'parcel',
    'typescript', 'ts-node', 'tsx', 'babel-core', '@babel/core',

    // Testing
    'jest', 'mocha', 'chai', 'vitest', 'jasmine',
    'sinon', 'supertest', 'nock', 'playwright', 'puppeteer',

    // Linting and formatting
    'eslint', 'prettier', 'husky', 'lint-staged', 'stylelint',

    // Frontend frameworks
    'react', 'vue', 'angular', 'svelte', 'preact', 'solid-js',

    // Meta frameworks
    'next', 'nuxt', 'gatsby', 'remix', 'astro', 'sveltekit',

    // State management
    'redux', 'mobx', 'zustand', 'jotai', 'recoil', 'pinia',

    // Database and ORM
    'mongoose', 'prisma', 'sequelize', 'typeorm', 'knex',
    'pg', 'mysql2', 'sqlite3', 'redis', 'ioredis',

    // Auth
    'passport', 'jsonwebtoken', 'bcrypt', 'argon2',
    'express-session', 'cookie-parser', 'csrf',

    // API and server
    'express', 'fastify', 'koa', 'hapi', 'nestjs',
    'cors', 'helmet', 'morgan', 'compression', 'body-parser',

    // Real time
    'socket.io', 'ws', 'uws', 'sse', 'eventsource',

    // File handling
    'multer', 'formidable', 'busboy', 'sharp', 'jimp',
    'archiver', 'unzipper', 'glob', 'minimatch', 'chokidar',

    // Parsing and templating
    'cheerio', 'jsdom', 'marked', 'showdown', 'handlebars',
    'ejs', 'pug', 'nunjucks', 'mustache',

    // Crypto and security
    'crypto-js', 'node-forge', 'jsrsasign', 'jose', 'otpauth',

    // Process and system
    'nodemon', 'pm2', 'concurrently', 'cross-spawn', 'execa',
    'shelljs', 'which', 'open', 'got',

    // Semver and package utils
    'semver', 'validate-npm-package-name', 'pacote', 'npm-registry-fetch',

    // CSS tooling
    'tailwindcss', 'postcss', 'autoprefixer', 'sass', 'less',
    'styled-components', 'emotion', 'linaria',

    // Logging
    'winston', 'pino', 'bunyan', 'debug', 'loglevel',

    // Queue and jobs
    'bull', 'bullmq', 'agenda', 'bee-queue', 'node-cron',

    // AI and ML
    'openai', '@anthropic-ai/sdk', 'langchain', '@langchain/core',
    'ollama', 'transformers', '@huggingface/inference',

    // Cloud SDKs
    '@aws-sdk/client-s3', '@aws-sdk/client-ec2',
    '@google-cloud/storage', '@azure/storage-blob',

    // Previously attacked packages
    '@ctrl/tinycolor', 'ngx-bootstrap', 'nx',
    'telnyx', 'litellm',

    // Package management
    'npm', 'yarn', 'pnpm',

    // Misc high value
    'lodash', 'async', 'bluebird', 'rxjs', 'immer',
    'zod', 'yup', 'joi', 'ajv', 'validator'
  ].filter((v, i, a) => a.indexOf(v) === i); // dedupe
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
