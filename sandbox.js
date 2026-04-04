const { execSync, spawn } = require('child_process');
const fs = require('fs');

function loadWhitelist() {
  try {
    return JSON.parse(fs.readFileSync('/root/pakrat/whitelist.json'));
  } catch (e) {
    return {};
  }
}

function runSandbox(packageName, version) {
  const containerName = `pakrat-${packageName}-${Date.now()}`;
  const captureFile = `/tmp/${containerName}.pcap`;

  const results = {
    package: packageName,
    version,
    networkCalls: [],
    suspiciousActivity: [],
    error: null
  };

  let tcpdump = null;

  try {
    console.log(`  [sandbox] starting network monitor...`);

    tcpdump = spawn('tcpdump', [
      '-i', 'docker0',
      '-w', captureFile,
      '-n',
      'not', 'port', '22'
    ]);

    execSync('sleep 1');

    console.log(`  [sandbox] installing ${packageName}@${version} in container...`);

    const output = execSync(`
      docker run --rm \
        --name ${containerName} \
        --memory 256m \
        --cpus 0.5 \
        node:22-alpine \
        sh -c "mkdir -p /app && cd /app && npm install ${packageName}@${version} 2>&1 | head -100"
    `, { timeout: 60000 }).toString();

    tcpdump.kill('SIGTERM');
    execSync('sleep 1');

    // Parse capture for DNS lookups only - cleaner signal
    try {
      const whitelist = loadWhitelist();
      const packageWhitelist = whitelist[packageName]?.allowedDomains || [];

      const allowedDomains = [
        'registry.npmjs.org',
        'nodejs.org',
        'npmjs.com',
        'npmjs.org',
        'cloudflare.com',
        ...packageWhitelist
      ];

      const dnsLookups = execSync(
        `tcpdump -r ${captureFile} -n 2>/dev/null | grep "A?" | grep -oP "A\\?\\s+\\K[^\\s]+" | sort -u`
      ).toString().trim().split('\n').filter(Boolean);

      const suspiciousDomains = dnsLookups.filter(domain => {
        return !allowedDomains.some(allowed => domain.includes(allowed));
      });

      if (suspiciousDomains.length > 0) {
        results.networkCalls = suspiciousDomains;
        results.suspiciousActivity.push(`SUSPICIOUS DNS LOOKUPS: ${suspiciousDomains.join(', ')}`);
      }

    } catch (e) {
      // No DNS lookups - good
    }

    // Pattern matching on install output as secondary signal
    const suspiciousPatterns = [
      { pattern: /\.ssh/i, label: 'SSH directory access' },
      { pattern: /\.aws/i, label: 'AWS credentials access' },
      { pattern: /process\.env/i, label: 'environment variable access' },
      { pattern: /base64/i, label: 'base64 encoding detected' },
    ];

    for (const { pattern, label } of suspiciousPatterns) {
      if (pattern.test(output)) {
        results.suspiciousActivity.push(label);
      }
    }

    results.installOutput = output.slice(0, 500);

  } catch (err) {
    if (tcpdump) tcpdump.kill('SIGTERM');
    if (err.signal === 'SIGTERM') {
      results.error = 'timeout';
      results.suspiciousActivity.push('TIMEOUT - possible infinite loop');
    } else {
      results.error = err.message.slice(0, 200);
    }
  } finally {
    try { fs.unlinkSync(captureFile); } catch (e) {}
  }

  return results;
}

module.exports = { runSandbox };
