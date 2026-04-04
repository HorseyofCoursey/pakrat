const { spawn, execSync } = require('child_process');
const fs = require('fs');

function runEbpfSandbox(packageName, version) {
  const containerName = `pakrat-ebpf-${packageName}-${Date.now()}`;
  const logFile = `/tmp/${containerName}-ebpf.log`;
  const bpfScriptFile = `/tmp/${containerName}.bt`;

  const results = {
    package: packageName,
    version,
    processes: [],
    networkConnections: [],
    fileAccess: [],
    suspiciousActivity: [],
    error: null
  };

  const bpfScript = [
    'tracepoint:syscalls:sys_enter_execve {',
    '  printf("EXEC %s\\n", str(args->filename));',
    '}',
    'tracepoint:syscalls:sys_enter_openat {',
    '  printf("OPEN %s\\n", str(args->filename));',
    '}'
  ].join('\n');

  fs.writeFileSync(bpfScriptFile, bpfScript);
  fs.writeFileSync(logFile, '');

  let bpftrace = null;

  const dockerProcesses = [
    'containerd', 'runc', 'docker', 'iptables',
    'open-iscsi', 'systemd', 'xtables'
  ];

  const dockerFiles = [
    '/run/credentials',
    '/run/user/0/credentials',
    '/run/docker',
    'pam.d',
    'overlayfs',
    'netns',
    'containerd',
    '.mount'
  ];

  const suspiciousProcesses = [
    'curl', 'wget', 'nc ', 'netcat', 'ncat',
    'python', 'perl', 'ruby', 'php', 'powershell'
  ];

  // Only flag files that are genuinely sensitive
  // /etc/passwd is normal, these are not
  // Files that should never be touched by a package install
  const suspiciousFiles = [
    'id_rsa',
    'id_ed25519',
    '/.ssh/',
    '/.aws/',
    '/proc/self/environ'
  ];

  try {
    console.log(`  [ebpf] attaching kernel probes...`);

    bpftrace = spawn('sh', ['-c', `bpftrace ${bpfScriptFile} >> ${logFile} 2>/tmp/bpftrace-err.log`], {
      stdio: 'ignore',
      detached: false
    });

    let attached = false;
    const start = Date.now();
    while (!attached && Date.now() - start < 5000) {
      execSync('sleep 0.5');
      try {
        const err = fs.readFileSync('/tmp/bpftrace-err.log').toString();
        if (err.includes('Attaching')) attached = true;
      } catch (e) {}
    }

    console.log(`  [ebpf] probes attached, installing ${packageName}@${version}...`);

    execSync(`
      docker run --rm \
        --name ${containerName} \
        --pid host \
        --memory 256m \
        --cpus 0.5 \
        node:22-alpine \
        sh -c "mkdir -p /app && cd /app && npm install ${packageName}@${version} 2>&1"
    `, { timeout: 60000 });

    execSync('sleep 3');
    bpftrace.kill('SIGTERM');
    execSync('sleep 2');

    const log = fs.readFileSync(logFile).toString();
    const lines = log.split('\n').filter(Boolean);

    console.log(`  [ebpf] captured ${lines.length} kernel events`);

    for (const line of lines) {
      if (line.startsWith('EXEC')) {
        const proc = line.replace('EXEC', '').trim();
        if (dockerProcesses.some(d => proc.includes(d))) continue;
        if (suspiciousProcesses.some(p => proc.includes(p))) {
          if (!results.processes.includes(proc)) {
            results.processes.push(proc);
            results.suspiciousActivity.push(`SUSPICIOUS PROCESS: ${proc}`);
          }
        }
      }

      if (line.startsWith('OPEN')) {
        const file = line.replace('OPEN', '').trim();
        if (dockerFiles.some(d => file.includes(d))) continue;
        if (suspiciousFiles.some(f => file.includes(f))) {
          if (!results.fileAccess.includes(file)) {
            results.fileAccess.push(file);
            results.suspiciousActivity.push(`SENSITIVE FILE ACCESS: ${file}`);
          }
        }
      }
    }

  } catch (err) {
    if (bpftrace) bpftrace.kill('SIGTERM');
    results.error = err.message.slice(0, 200);
  } finally {
    try { fs.unlinkSync(logFile); } catch (e) {}
    try { fs.unlinkSync(bpfScriptFile); } catch (e) {}
  }

  return results;
}

module.exports = { runEbpfSandbox };
