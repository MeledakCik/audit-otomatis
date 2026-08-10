// app/api/scan/ssl/route.ts
import { NextRequest, NextResponse } from "next/server";
import tls from "tls";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// ============ KONFIGURASI ============
const TIMEOUT_MS = 6000;
const RATE_LIMIT = 10;
const ALLOWED_PORTS = [443, 8443, 2083, 2087];

// ============ CACHE & RATE LIMIT ============
const scanCache = new Map<string, { data: any; timestamp: number }>();
const rateLimit = new Map<string, { count: number; resetTime: number }>();
const CACHE_TTL = 5 * 60 * 1000;

// ============ INTERFACE ============
interface CertificateInfo {
  subject: string;
  issuer: string;
  san: string[];
  valid_from: string;
  valid_to: string;
  days_left: number;
  serial: string;
  fingerprint_sha256: string;
  sig_algo: string;
  key_type: string;
  key_bits: number;
  self_signed: boolean;
  chain_length: number;
  raw?: string;
}

interface TLSInfo {
  negotiated_version: string;
  supports_deprecated_tls: string[];
  alpn: string | null;
}

interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  type: string;
  description?: string;
}

interface ScanResult {
  host: string;
  port: number;
  grade: string;
  cert: CertificateInfo;
  tls: TLSInfo;
  findings: Finding[];
  scanned_at: string;
  scan_duration_ms: number;
}

// ============ HELPER FUNCTIONS ============
function getClientIP(request: NextRequest): string {
  return request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
         request.headers.get('x-real-ip') || 
         'unknown';
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = rateLimit.get(ip);
  
  if (!record || now > record.resetTime) {
    rateLimit.set(ip, { count: 1, resetTime: now + 60000 });
    return true;
  }
  
  if (record.count >= RATE_LIMIT) return false;
  record.count++;
  return true;
}

function getCached(key: string): any | null {
  const cached = scanCache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  scanCache.delete(key);
  return null;
}

function setCache(key: string, data: any): void {
  scanCache.set(key, { data, timestamp: Date.now() });
}

function extractHostname(input: string): { host: string; port: number } {
  let raw = input.trim();
  let port = 443;
  
  // Remove protocol
  raw = raw.replace(/^https?:\/\//, '');
  
  // Extract port if specified
  const portMatch = raw.match(/:(\d+)$/);
  if (portMatch) {
    port = parseInt(portMatch[1]);
    raw = raw.replace(/:(\d+)$/, '');
  }
  
  // Remove path
  raw = raw.split('/')[0];
  
  return { host: raw, port };
}

function formatDate(date: Date): string {
  return date.toISOString().replace('T', ' ').substring(0, 19);
}

function calculateDaysLeft(validTo: Date): number {
  const now = new Date();
  const diff = validTo.getTime() - now.getTime();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

function getGrade(findings: Finding[], daysLeft: number): string {
  const hasCritical = findings.some(f => f.severity === "critical");
  if (hasCritical) return "F";
  
  const hasHigh = findings.some(f => f.severity === "high");
  const hasMedium = findings.some(f => f.severity === "medium");
  
  if (daysLeft < 7) return "F";
  if (daysLeft < 30) return "D";
  if (daysLeft < 90) return "C";
  
  if (hasHigh) return "B";
  if (hasMedium) return "B";
  
  return "A+";
}

function detectKeyTypeAndBits(cert: any): { type: string; bits: number } {
  try {
    if (cert.pubkey) {
      const pem = cert.pubkey.toString('base64');
      if (pem.includes('MIIB')) {
        return { type: 'ECDSA', bits: 256 };
      }
      const bits = cert.pubkey.bitLength || 2048;
      return { type: 'RSA', bits };
    }
  } catch {}
  return { type: 'Unknown', bits: 0 };
}

function parseSANS(cert: any): string[] {
  try {
    if (cert.subjectaltname) {
      return cert.subjectaltname
        .split(', ')
        .map((s: string) => s.replace(/^(DNS|IP Address):/, ''))
        .filter((s: string) => s);
    }
  } catch {}
  return [];
}

// Check deprecated TLS using secureConnect with different secureProtocol
function checkDeprecatedTLS(host: string, port: number): Promise<string[]> {
  return new Promise((resolve) => {
    const deprecated: string[] = [];
    // Use secureProtocol options for different TLS versions
    const versions = [
      { name: 'TLSv1.0', protocol: 'TLSv1_method' },
      { name: 'TLSv1.1', protocol: 'TLSv1_1_method' }
    ];
    let completed = 0;
    
    if (versions.length === 0) {
      resolve(deprecated);
      return;
    }
    
    versions.forEach((version) => {
      let socket: tls.TLSSocket | null = null;
      let timer: NodeJS.Timeout | null = null;
      
      try {
        socket = tls.connect({
          host,
          port,
          servername: host,
          secureProtocol: version.protocol,
          timeout: 3000,
          rejectUnauthorized: false,
        });
        
        timer = setTimeout(() => {
          if (socket) {
            socket.destroy();
          }
          completed++;
          if (completed === versions.length) {
            resolve(deprecated);
          }
        }, 3000);
        
        socket.once('secureConnect', () => {
          if (timer) clearTimeout(timer);
          deprecated.push(version.name);
          if (socket) socket.destroy();
          completed++;
          if (completed === versions.length) {
            resolve(deprecated);
          }
        });
        
        socket.once('error', () => {
          if (timer) clearTimeout(timer);
          if (socket) socket.destroy();
          completed++;
          if (completed === versions.length) {
            resolve(deprecated);
          }
        });
        
        socket.once('close', () => {
          if (timer) clearTimeout(timer);
          completed++;
          if (completed === versions.length) {
            resolve(deprecated);
          }
        });
        
      } catch (err) {
        if (timer) clearTimeout(timer);
        if (socket) socket.destroy();
        completed++;
        if (completed === versions.length) {
          resolve(deprecated);
        }
      }
    });
    
    // Safety timeout
    setTimeout(() => {
      resolve(deprecated);
    }, 5000);
  });
}

function performTLSHandshake(host: string, port: number): Promise<{
  cert: any;
  tlsVersion: string;
  alpn: string | null;
  chain: any[];
}> {
  return new Promise((resolve, reject) => {
    let socket: tls.TLSSocket | null = null;
    let timer: NodeJS.Timeout | null = null;
    
    try {
      socket = tls.connect({
        host,
        port,
        servername: host,
        timeout: TIMEOUT_MS,
        rejectUnauthorized: false,
      });
      
      timer = setTimeout(() => {
        if (socket) socket.destroy();
        reject(new Error(`Connection timeout after ${TIMEOUT_MS}ms`));
      }, TIMEOUT_MS);
      
      socket.once('secureConnect', () => {
        if (timer) clearTimeout(timer);
        
        if (!socket) {
          reject(new Error('Socket is null'));
          return;
        }
        
        const cert = socket.getPeerCertificate(true);
        const tlsVersion = socket.getProtocol() || 'TLSv1.3';
        const alpn = socket.alpnProtocol || null;
        
        const chain: any[] = [];
        let currentCert = cert;
        while (currentCert) {
          chain.push(currentCert);
          currentCert = currentCert.issuerCertificate;
          if (currentCert === chain[chain.length - 1]) break;
        }
        
        socket.destroy();
        resolve({ cert, tlsVersion, alpn, chain });
      });
      
      socket.once('error', (err) => {
        if (timer) clearTimeout(timer);
        if (socket) socket.destroy();
        reject(err);
      });
      
      socket.once('close', () => {
        if (timer) clearTimeout(timer);
      });
      
    } catch (err) {
      if (timer) clearTimeout(timer);
      if (socket) socket.destroy();
      reject(err);
    }
  });
}

// ============ MAIN HANDLER ============
export async function GET() {
  return NextResponse.json({
    status: "SSL/TLS Scanner API",
    message: "POST with { domain: 'example.com' } or { domain: 'example.com:8443' }",
    features: [
      "Certificate extraction",
      "Security grading",
      "TLS version detection",
      "Deprecated TLS check",
      "SAN extraction",
    ],
  });
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  console.log("🔐 SSL/TLS Scanner API called");
  
  // Rate limiting
  const ip = getClientIP(request);
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait a moment." },
      { status: 429 }
    );
  }
  
  let host = "";
  let port = 443;
  
  try {
    const body = await request.json().catch(() => null);
    
    if (!body || !body.domain || typeof body.domain !== "string") {
      return NextResponse.json(
        { error: "Field `domain` is required." },
        { status: 400 }
      );
    }
    
    const extracted = extractHostname(body.domain);
    host = extracted.host;
    port = extracted.port;
    
    // Check if port is allowed
    if (!ALLOWED_PORTS.includes(port)) {
      return NextResponse.json(
        { error: `Port ${port} is not allowed. Allowed ports: ${ALLOWED_PORTS.join(', ')}` },
        { status: 400 }
      );
    }
    
    // Check cache
    const cacheKey = `${host}:${port}`;
    const cached = getCached(cacheKey);
    if (cached) {
      console.log(`✅ Returning cached result for ${cacheKey}`);
      return NextResponse.json({
        ...cached,
        cached: true,
        cachedAt: new Date().toISOString(),
      });
    }
    
    console.log(`🔐 Connecting to ${host}:${port}`);
    
    // Perform TLS handshake
    const { cert, tlsVersion, alpn, chain } = await performTLSHandshake(host, port);
    
    if (!cert || Object.keys(cert).length === 0) {
      return NextResponse.json(
        { error: "No certificate received from server." },
        { status: 422 }
      );
    }
    
    // Extract certificate information
    const subject = cert.subject?.CN || cert.subject?.O || cert.subject?.OU || 'Unknown';
    const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
    const san = parseSANS(cert);
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const daysLeft = calculateDaysLeft(validTo);
    const serial = cert.serialNumber || 'Unknown';
    const fingerprint = cert.fingerprint256 || 'Unknown';
    const sigAlgo = cert.sigAlg || 'Unknown';
    const { type: keyType, bits: keyBits } = detectKeyTypeAndBits(cert);
    const selfSigned = cert.issuer?.CN === cert.subject?.CN;
    const chainLength = chain.length;
    
    // Check deprecated TLS
    const deprecatedTLS = await checkDeprecatedTLS(host, port);
    
    // Build findings
    const findings: Finding[] = [];
    
    // Check expiry
    if (daysLeft < 0) {
      findings.push({
        severity: "critical",
        title: "Certificate has expired",
        type: "EXPIRED",
        description: `Certificate expired on ${formatDate(validTo)}`,
      });
    } else if (daysLeft < 7) {
      findings.push({
        severity: "critical",
        title: "Certificate expires very soon",
        type: "EXPIRY_CRITICAL",
        description: `Certificate expires in ${daysLeft} days (${formatDate(validTo)})`,
      });
    } else if (daysLeft < 30) {
      findings.push({
        severity: "high",
        title: "Certificate expires soon",
        type: "EXPIRY_SOON",
        description: `Certificate expires in ${daysLeft} days (${formatDate(validTo)})`,
      });
    } else if (daysLeft < 90) {
      findings.push({
        severity: "medium",
        title: "Certificate expires in less than 90 days",
        type: "EXPIRY_MEDIUM",
        description: `Certificate expires in ${daysLeft} days (${formatDate(validTo)})`,
      });
    }
    
    // Check self-signed
    if (selfSigned) {
      findings.push({
        severity: "high",
        title: "Self-signed certificate",
        type: "SELF_SIGNED",
        description: "Certificate is self-signed and may not be trusted by browsers",
      });
    }
    
    // Check weak signature
    if (sigAlgo.toLowerCase().includes('sha1')) {
      findings.push({
        severity: "high",
        title: "Weak signature algorithm",
        type: "WEAK_SIG",
        description: `Using ${sigAlgo} which is considered weak and deprecated`,
      });
    }
    
    // Check key strength
    if (keyType === 'RSA' && keyBits < 2048) {
      findings.push({
        severity: "high",
        title: "Weak key strength",
        type: "WEAK_KEY",
        description: `RSA ${keyBits}-bit key is below recommended minimum of 2048 bits`,
      });
    }
    
    // Check deprecated TLS
    if (deprecatedTLS.length > 0) {
      findings.push({
        severity: "medium",
        title: "Deprecated TLS versions supported",
        type: "DEPRECATED_TLS",
        description: `Server supports: ${deprecatedTLS.join(', ')} - these versions have known vulnerabilities`,
      });
    }
    
    // Wildcard info
    const hasWildcard = san.some(s => s.startsWith('*.'));
    if (hasWildcard) {
      findings.push({
        severity: "info",
        title: "Wildcard certificate detected",
        type: "WILDCARD",
        description: "Certificate uses wildcard SAN, which may increase attack surface",
      });
    }
    
    // Chain info
    if (chainLength > 3) {
      findings.push({
        severity: "info",
        title: "Long certificate chain",
        type: "LONG_CHAIN",
        description: `Certificate chain has ${chainLength} certificates, which may impact performance`,
      });
    }
    
    // Calculate grade
    const grade = getGrade(findings, daysLeft);
    
    const result: ScanResult = {
      host,
      port,
      grade,
      cert: {
        subject,
        issuer,
        san,
        valid_from: validFrom.toISOString(),
        valid_to: validTo.toISOString(),
        days_left: daysLeft,
        serial,
        fingerprint_sha256: fingerprint,
        sig_algo: sigAlgo,
        key_type: keyType,
        key_bits: keyBits,
        self_signed: selfSigned,
        chain_length: chainLength,
      },
      tls: {
        negotiated_version: tlsVersion,
        supports_deprecated_tls: deprecatedTLS,
        alpn,
      },
      findings,
      scanned_at: new Date().toISOString(),
      scan_duration_ms: Date.now() - startTime,
    };
    
    // Cache result
    setCache(cacheKey, result);
    
    console.log(`✅ Complete in ${result.scan_duration_ms}ms`);
    return NextResponse.json(result);
    
  } catch (error) {
    console.error("❌ Error:", error);
    
    let errorMessage = "Failed to scan SSL/TLS certificate.";
    if (error instanceof Error) {
      if (error.message.includes('ECONNREFUSED')) {
        errorMessage = `Connection refused to ${host || 'unknown'}:${port}. Server may not be running.`;
      } else if (error.message.includes('ENOTFOUND')) {
        errorMessage = `Hostname ${host || 'unknown'} could not be resolved.`;
      } else if (error.message.includes('timeout')) {
        errorMessage = `Connection timeout to ${host || 'unknown'}:${port}.`;
      } else {
        errorMessage = error.message;
      }
    }
    
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}