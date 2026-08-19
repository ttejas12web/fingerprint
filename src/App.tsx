import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Fingerprint, Shield, ShieldCheck, ShieldAlert, Cpu, Database, LockKeyhole } from 'lucide-react';
import { startRegistration, startAuthentication, platformAuthenticatorIsAvailable } from '@simplewebauthn/browser';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';

type AuthState = 'idle' | 'scanning' | 'verifying' | 'success' | 'error';

type IdentifiedUser = {
  id: string;
  name: string;
  employeeId: string;
};

type ApiErrorPayload = { error?: string };
type VerificationPayload = ApiErrorPayload & {
  verified?: boolean;
  user?: IdentifiedUser;
};

async function readApiJson<T>(response: Response): Promise<T> {
  const contentType = response.headers.get('Content-Type') ?? '';
  if (!contentType.includes('application/json')) {
    throw new Error(
      `Biometric API unavailable (HTTP ${response.status}). The Cloudflare Worker backend is not active for /api/*.`
    );
  }

  const payload = await response.json() as T & ApiErrorPayload;
  if (!response.ok) {
    throw new Error(payload.error || `Biometric API request failed (HTTP ${response.status}).`);
  }
  return payload;
}

type WebAuthnFeature = 'publickey-credentials-create' | 'publickey-credentials-get';

const getWebAuthnBlockReason = (feature: WebAuthnFeature) => {
  if (typeof window === 'undefined') return 'Biometric authentication is only available in a browser.';
  if (!window.isSecureContext) return 'Biometric authentication requires a secure HTTPS connection.';
  if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials) {
    return 'This browser does not expose a WebAuthn biometric service.';
  }

  const policy = (document as any).permissionsPolicy ?? (document as any).featurePolicy;
  if (window.self !== window.top && policy?.allowsFeature) {
    try {
      if (!policy.allowsFeature(feature)) {
        return 'AI Studio preview blocks biometric access in an embedded frame. Open the secure scanner in a new tab.';
      }
    } catch {
      // Older browsers may not recognize the permissions-policy feature name.
    }
  }

  return null;
};

const triggerHaptic = (type: 'scan' | 'success' | 'error') => {
  if (typeof navigator !== 'undefined' && 'vibrate' in navigator) {
    try {
      switch (type) {
        case 'scan':
          // Subtle pulse to indicate the scanner is active
          navigator.vibrate([50, 100, 50]);
          break;
        case 'success':
          // Distinct success confirmation vibration
          navigator.vibrate([100, 50, 100, 50, 200]);
          break;
        case 'error':
          // Stuttering error vibration
          navigator.vibrate([50, 50, 50, 50, 50, 50]);
          break;
      }
    } catch (e) {
      console.warn('Vibration API blocked or unsupported', e);
    }
  }
};

export default function App() {
  const [authState, setAuthState] = useState<AuthState>('idle');
  const [logs, setLogs] = useState<{ id: string; text: string; type: 'info' | 'success' | 'error' | 'sec' }[]>([]);
  const [enrollmentName, setEnrollmentName] = useState('');
  const [employeeId, setEmployeeId] = useState('');
  const [identifiedUser, setIdentifiedUser] = useState<IdentifiedUser | null>(null);
  const [userCount, setUserCount] = useState(0);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const embeddedPreview = typeof window !== 'undefined' && window.self !== window.top;
  const webAuthnBlockReason =
    getWebAuthnBlockReason('publickey-credentials-create') ??
    getWebAuthnBlockReason('publickey-credentials-get');

  const addLog = (text: string, type: 'info' | 'success' | 'error' | 'sec' = 'info') => {
    setLogs((prev) => [...prev, { id: Math.random().toString(36).substr(2, 9), text, type }]);
  };

  const refreshUserCount = async () => {
    try {
      const response = await fetch('/api/users');
      const payload = await readApiJson<{ count?: number }>(response);
      setUserCount(Number(payload.count || 0));
    } catch {
      // The live registry count will refresh after the next successful request.
    }
  };

  useEffect(() => {
    refreshUserCount();
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const openStandalone = () => {
    const opened = window.open(window.location.href, '_blank', 'noopener,noreferrer');
    if (!opened) {
      addLog('[INFO] Pop-up blocked. Copy the app URL into regular Safari, Chrome, or Edge.', 'info');
    }
  };

  const ensurePlatformAuthenticator = async () => {
    try {
      if (await platformAuthenticatorIsAvailable()) return true;
    } catch {
      // A false result and a capability-check failure use the same recovery path.
    }

    setAuthState('idle');
    setLogs([]);
    addLog(
      '[INFO] This browser cannot reach the laptop biometric authenticator. Open the app in regular Safari, Chrome, or Edge and make sure Touch ID or Windows Hello is configured.',
      'info'
    );
    return false;
  };

  // Handle Registration (Vaulting new fingerprint)
  const handleRegister = async () => {
    if (authState === 'scanning' || authState === 'verifying') return;
    const blockReason = getWebAuthnBlockReason('publickey-credentials-create');
    if (blockReason) {
      setAuthState('idle');
      setLogs([]);
      addLog(`[INFO] ${blockReason}`, 'info');
      return;
    }

    const name = enrollmentName.trim();
    const userId = employeeId.trim().toUpperCase();
    if (!name || !userId) {
      setAuthState('idle');
      setLogs([]);
      addLog('[INFO] Enter the person\'s name and user ID before enrollment.', 'info');
      return;
    }

    if (!(await ensurePlatformAuthenticator())) return;

    setIdentifiedUser(null);
    setAuthState('scanning');
    triggerHaptic('scan');
    setLogs([]);
    addLog('[SYS] Initializing Photoelectric Array...', 'info');
    
    try {
      addLog(`[SEC] Creating a compatible device credential for ${name} (${userId})...`, 'sec');
      const resp = await fetch('/api/generate-registration-options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, employeeId: userId })
      });
      
      const options = await readApiJson<PublicKeyCredentialCreationOptionsJSON & ApiErrorPayload>(resp);
      if (options.error) throw new Error(options.error);

      addLog('[SYS] Awaiting physical biometric interaction...', 'info');
      addLog('[SYS] Emitting photon pulse for optical sensor capture...', 'info');
      
      let attResp;
      try {
        attResp = await startRegistration({ optionsJSON: options });
      } catch (err: any) {
        if (err.name === 'NotAllowedError') {
          setAuthState('idle');
          addLog(
            embeddedPreview
              ? '[INFO] The biometric prompt was blocked or cancelled in the embedded preview. Open the secure scanner in a new tab and try again.'
              : '[INFO] No compatible credential was created or selected. Use regular Safari, Chrome, or Edge with Touch ID or Windows Hello enabled, then try again.',
            'info'
          );
          return;
        }
        throw err;
      }

      setAuthState('verifying');
      addLog('[SEC] Device approved credential creation.', 'sec');
      addLog('[SEC] Fingerprint template remains private inside the platform authenticator.', 'sec');
      addLog('[SEC] Linking the credential ID and public key to the named user record...', 'sec');

      const verificationResp = await fetch('/api/verify-registration', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          employeeId: userId,
          response: attResp,
        }),
      });

      const verificationJSON = await readApiJson<VerificationPayload>(verificationResp);
      
      if (verificationJSON.verified && verificationJSON.user) {
        setAuthState('success');
        setIdentifiedUser(verificationJSON.user);
        triggerHaptic('success');
        await refreshUserCount();
        addLog(`[SUCCESS] ${verificationJSON.user.name} enrolled. The database stores the credential ID and public key, never the fingerprint.`, 'success');
      } else {
        setAuthState('error');
        triggerHaptic('error');
        addLog(`[ERROR] Vaulting failed: ${verificationJSON.error || 'Unknown error'}`, 'error');
      }

    } catch (error: any) {
      setAuthState('error');
      triggerHaptic('error');
      addLog(`[ERROR] ${error.message}`, 'error');
    }
  };

  // Handle Authentication (Verifying existing fingerprint)
  const handleAuthenticate = async () => {
    if (authState === 'scanning' || authState === 'verifying') return;
    const blockReason = getWebAuthnBlockReason('publickey-credentials-get');
    if (blockReason) {
      setAuthState('idle');
      setLogs([]);
      addLog(`[INFO] ${blockReason}`, 'info');
      return;
    }
    if (!(await ensurePlatformAuthenticator())) return;

    setIdentifiedUser(null);
    setAuthState('scanning');
    triggerHaptic('scan');
    setLogs([]);
    addLog('[SYS] Initializing Photoelectric Array...', 'info');
    
    try {
      addLog('[SEC] Requesting an identification challenge for enrolled credentials...', 'sec');
      const resp = await fetch('/api/generate-identification-options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      
      const payload = await readApiJson<PublicKeyCredentialRequestOptionsJSON & {
        requestId: string;
        error?: string;
      }>(resp);
      if (payload.error) throw new Error(payload.error);
      const { requestId, error: _error, ...options } = payload;

      addLog('[SYS] Emitting photon pulse for optical sensor capture...', 'info');
      addLog('[SYS] Awaiting physical biometric interaction...', 'info');
      
      let asseResp;
      try {
        asseResp = await startAuthentication({ optionsJSON: options });
      } catch (err: any) {
         if (err.name === 'NotAllowedError') {
          setAuthState('idle');
          addLog(
            embeddedPreview
              ? '[INFO] The biometric prompt was blocked or cancelled in the embedded preview. Open the secure scanner in a new tab and try again.'
              : '[INFO] No compatible credential was created or selected. Use regular Safari, Chrome, or Edge with Touch ID or Windows Hello enabled, then try again.',
            'info'
          );
          return;
        }
        throw err;
      }

      setAuthState('verifying');
      addLog('[SEC] Local user verification completed by the platform authenticator.', 'sec');
      addLog('[SEC] Signing challenge with the private credential key...', 'sec');
      addLog('[SEC] Matching the verified credential ID to the user database...', 'sec');

      const verificationResp = await fetch('/api/verify-identification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId,
          response: asseResp,
        }),
      });

      const verificationJSON = await readApiJson<VerificationPayload>(verificationResp);
      
      if (verificationJSON.verified && verificationJSON.user) {
        setAuthState('success');
        setIdentifiedUser(verificationJSON.user);
        triggerHaptic('success');
        addLog(`[SUCCESS] Identity confirmed: ${verificationJSON.user.name} // ${verificationJSON.user.employeeId}`, 'success');
      } else {
        setAuthState('error');
        triggerHaptic('error');
        addLog(`[ERROR] Verification failed: ${verificationJSON.error || 'Unknown error'}`, 'error');
      }

    } catch (error: any) {
      setAuthState('error');
      triggerHaptic('error');
      addLog(`[ERROR] ${error.message}`, 'error');
    }
  };

  const getSensorColor = () => {
    switch (authState) {
      case 'idle': return 'text-cyan-500/50 shadow-cyan-500/20 border-cyan-500/20';
      case 'scanning': return 'text-cyan-400 shadow-cyan-400/80 border-cyan-400/50';
      case 'verifying': return 'text-blue-400 shadow-blue-400/80 border-blue-400/50';
      case 'success': return 'text-emerald-400 shadow-emerald-400/80 border-emerald-400/50';
      case 'error': return 'text-red-500 shadow-red-500/80 border-red-500/50';
    }
  };

  return (
    <div className="min-h-screen bg-[#050508] text-slate-300 font-sans selection:bg-cyan-500/30 flex flex-col overflow-hidden relative select-none">
      {/* Background Grids & FX */}
      <div className="absolute inset-0 z-0 opacity-20 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 50% 50%, #1a1aff 0%, transparent 70%), radial-gradient(circle at 10% 10%, #00f2ff 0%, transparent 30%)' }}></div>
      
      {/* Header */}
      <header className="h-16 relative z-10 px-8 flex justify-between items-center border-b border-white/10 bg-black/40 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]"></div>
          <span className="font-mono tracking-[0.2em] text-xs uppercase font-bold text-white">Quantum-Bio Forensic v4.2</span>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex flex-col items-end hidden sm:flex">
            <span className="text-[10px] uppercase opacity-50 font-semibold">Vault Status</span>
            <span className="text-xs font-mono text-cyan-400">IDENTITY REGISTRY // {userCount} USERS</span>
          </div>
          <div className="h-8 w-[1px] bg-white/10 hidden sm:block"></div>
          <div className="text-right">
            <span className="text-xs font-mono block">SESSION: SECURE</span>
            <span className="text-[9px] opacity-40">ID: X99-FRN-8821</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative z-10 flex-1 flex flex-col lg:flex-row items-center justify-center p-6 gap-12 lg:gap-24 max-w-7xl mx-auto w-full">
        
        {/* Left Side: Controls & Info */}
        <div className="flex flex-col max-w-md w-full gap-4">
          <div className="bg-white/5 border border-white/10 rounded-xl p-4 flex-1">
            <h3 className="text-[10px] uppercase tracking-widest text-cyan-400 mb-4 font-bold">System Diagnostics</h3>
            <p className="text-[10px] text-slate-400 leading-relaxed font-mono opacity-80 mb-4">
              The laptop sensor and operating system perform the private biometric match locally.
              This registry never receives fingerprint images or templates; it identifies a person from the verified passkey credential linked to their user record.
            </p>
            <div className="mt-6 pt-4 border-t border-white/5">
              <h4 className="text-[9px] uppercase opacity-40 mb-2">Local API Integration</h4>
              <ul className="text-[10px] space-y-2 font-mono">
                <li className={`flex items-center gap-2 ${webAuthnBlockReason ? 'text-amber-400' : 'text-emerald-400'}`}>
                  <span className={`w-1 h-1 rounded-full ${webAuthnBlockReason ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
                  BIOMETRIC_SERVICE: {webAuthnBlockReason ? 'ACTION REQUIRED' : 'OK'}
                </li>
                <li className="flex items-center gap-2 text-emerald-400">
                  <span className="w-1 h-1 rounded-full bg-emerald-400"></span> SECURE_ENCLAVE: ACTIVE
                </li>
                <li className="flex items-center gap-2 text-cyan-400">
                  <span className="w-1 h-1 rounded-full bg-cyan-400"></span> USER_DATABASE: {userCount} IDENTITIES
                </li>
              </ul>
            </div>
          </div>

          {webAuthnBlockReason && (
            <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4 text-xs text-amber-100">
              <p className="font-mono leading-relaxed">{webAuthnBlockReason}</p>
              {embeddedPreview && (
                <button
                  onClick={openStandalone}
                  className="mt-3 w-full rounded-lg border border-amber-300/40 bg-amber-300/10 px-4 py-2 font-semibold text-amber-100 transition-colors hover:bg-amber-300/20"
                >
                  Open Secure Scanner in New Tab
                </button>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="text-[9px] font-mono uppercase tracking-widest text-slate-500">
              Person name
              <input
                value={enrollmentName}
                onChange={(event) => setEnrollmentName(event.target.value)}
                placeholder="e.g. Tejas Tapse"
                className="mt-1 w-full select-text rounded-lg border border-white/10 bg-black/50 px-3 py-2 text-xs normal-case tracking-normal text-white outline-none focus:border-cyan-500/60"
              />
            </label>
            <label className="text-[9px] font-mono uppercase tracking-widest text-slate-500">
              User ID
              <input
                value={employeeId}
                onChange={(event) => setEmployeeId(event.target.value)}
                placeholder="e.g. EMP-001"
                className="mt-1 w-full select-text rounded-lg border border-white/10 bg-black/50 px-3 py-2 text-xs normal-case tracking-normal text-white outline-none focus:border-cyan-500/60"
              />
            </label>
          </div>

          <div className="flex flex-col gap-4">
            <button 
              onClick={handleRegister}
              disabled={authState === 'scanning' || authState === 'verifying'}
              className="group relative px-6 py-4 bg-white/5 border border-white/10 hover:border-cyan-500/50 rounded-xl flex items-center justify-between overflow-hidden transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/0 via-cyan-500/5 to-cyan-500/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000"></div>
              <div className="flex items-center gap-4 relative z-10">
                <div className="p-2 bg-black/50 rounded-lg">
                  <Database className="w-5 h-5 text-cyan-500" />
                </div>
                <div className="text-left">
                  <div className="text-sm font-semibold text-white">Enroll Named User</div>
                  <div className="text-xs text-slate-500">Link this device credential to the user database</div>
                </div>
              </div>
            </button>

            <button 
              onClick={handleAuthenticate}
              disabled={authState === 'scanning' || authState === 'verifying'}
              className="group relative px-6 py-4 bg-white/5 border border-white/10 hover:border-cyan-500/50 rounded-xl flex items-center justify-between overflow-hidden transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/0 via-cyan-500/5 to-cyan-500/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000"></div>
              <div className="flex items-center gap-4 relative z-10">
                <div className="p-2 bg-black/50 rounded-lg">
                  <LockKeyhole className="w-5 h-5 text-cyan-500" />
                </div>
                <div className="text-left">
                  <div className="text-sm font-semibold text-white">Identify Person</div>
                  <div className="text-xs text-slate-500">Ask the laptop sensor, then find the matching user record</div>
                </div>
              </div>
            </button>
          </div>
        </div>

        {/* Right Side: Sensor Interface */}
        <div className="flex flex-col items-center gap-8">
          
          <div className="relative group cursor-pointer">
            <div className="absolute -inset-24 bg-cyan-500/10 rounded-full blur-[80px] pointer-events-none"></div>
            {/* Outer Ring */}
            <motion.div 
              animate={{
                rotate: authState === 'scanning' ? 360 : 0,
                scale: authState === 'success' ? 1.1 : 1,
              }}
              transition={{ duration: 3, ease: "linear", repeat: authState === 'scanning' ? Infinity : 0 }}
              className={`absolute -inset-4 border border-dashed rounded-full transition-colors duration-500 ${getSensorColor()}`}
            />
            
            {/* Sensor Button */}
            <motion.button
              onClick={handleAuthenticate}
              aria-label="Identify person with device biometric"
              whileTap={{ scale: 0.95 }}
              className={`relative w-64 h-64 rounded-full border-2 flex items-center justify-center bg-black transition-all duration-500 overflow-hidden ${getSensorColor()}`}
              style={{
                boxShadow: authState === 'scanning' ? '0 0 50px rgba(34, 211, 238, 0.4)' : 
                           authState === 'verifying' ? '0 0 50px rgba(96, 165, 250, 0.4)' :
                           authState === 'success' ? '0 0 50px rgba(52, 211, 153, 0.4)' :
                           authState === 'error' ? '0 0 50px rgba(239, 68, 68, 0.4)' :
                           '0 0 50px rgba(34, 211, 238, 0.2)',
              }}
            >
              <div className="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_center,_#22d3ee_0%,_transparent_70%)] pointer-events-none"></div>
              <div className="absolute inset-4 rounded-full border border-white/5 flex items-center justify-center pointer-events-none">
                <div className="absolute inset-4 rounded-full border border-white/10 pointer-events-none"></div>
              </div>
              <AnimatePresence mode="wait">
                {authState === 'idle' && (
                  <motion.div key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    <Fingerprint className="w-20 h-20" strokeWidth={1} />
                  </motion.div>
                )}
                {authState === 'scanning' && (
                  <motion.div key="scanning" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="relative">
                    <Fingerprint className="w-20 h-20 animate-pulse" strokeWidth={1.5} />
                    {/* Scanning Bar */}
                    <motion.div 
                      className="absolute left-[-20%] right-[-20%] h-1 bg-cyan-400 shadow-[0_0_15px_rgba(34,211,238,1)] rounded-full z-10"
                      animate={{ top: ['0%', '100%', '0%'] }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                    />
                  </motion.div>
                )}
                {authState === 'verifying' && (
                  <motion.div key="verifying" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    <Shield className="w-20 h-20 animate-pulse" strokeWidth={1} />
                  </motion.div>
                )}
                {authState === 'success' && (
                  <motion.div key="success" initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}>
                    <ShieldCheck className="w-20 h-20" strokeWidth={1.5} />
                  </motion.div>
                )}
                {authState === 'error' && (
                  <motion.div key="error" initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}>
                    <ShieldAlert className="w-20 h-20" strokeWidth={1.5} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.button>
          </div>

          <div className="text-center h-8">
            <AnimatePresence mode="wait">
              {authState === 'scanning' && (
                <motion.p key="scan" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="text-cyan-400 text-sm tracking-widest uppercase">
                  Awaiting Input...
                </motion.p>
              )}
              {authState === 'verifying' && (
                <motion.p key="verify" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="text-blue-400 text-sm tracking-widest uppercase">
                  Verifying Signature...
                </motion.p>
              )}
              {authState === 'success' && (
                <motion.p key="succ" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="text-emerald-400 text-sm tracking-widest uppercase">
                  Identity Confirmed
                </motion.p>
              )}
               {authState === 'error' && (
                <motion.p key="err" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="text-red-500 text-sm tracking-widest uppercase">
                  Authentication Failed
                </motion.p>
              )}
            </AnimatePresence>
          </div>

          {identifiedUser && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="min-w-64 rounded-xl border border-emerald-400/30 bg-emerald-400/10 px-5 py-3 text-center"
            >
              <div className="text-[9px] font-mono uppercase tracking-[0.25em] text-emerald-300">Identified user</div>
              <div className="mt-1 text-lg font-semibold text-white">{identifiedUser.name}</div>
              <div className="font-mono text-xs text-emerald-300">{identifiedUser.employeeId}</div>
            </motion.div>
          )}

        </div>
      </main>

      {/* Bottom Log Console */}
      <div className="relative z-10 bg-white/5 border-t border-white/10 p-4 h-48 lg:h-64 flex flex-col backdrop-blur-xl mt-auto mx-6 mb-6 rounded-t-xl">
        <div className="flex items-center gap-2 mb-3">
          <h3 className="text-[10px] font-bold text-white uppercase tracking-widest">Activity Logs</h3>
        </div>
        <div className="flex-1 overflow-y-auto font-mono text-[9px] space-y-3 pr-4 custom-scrollbar opacity-80">
          {logs.length === 0 ? (
            <p className="text-white/40 italic">System ready. Select an action to begin.</p>
          ) : (
            <AnimatePresence initial={false}>
              {logs.map((log) => (
                <motion.div 
                  key={log.id} 
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className={`border-l pl-2 uppercase tracking-wider
                    ${log.type === 'info' ? 'border-white/10 text-white/50' : ''}
                    ${log.type === 'sec' ? 'border-cyan-500/30 text-cyan-400' : ''}
                    ${log.type === 'success' ? 'border-emerald-500/30 text-emerald-400' : ''}
                    ${log.type === 'error' ? 'border-red-500/30 text-red-400' : ''}
                  `}
                >
                  <span className="opacity-50 mr-2">[{new Date().toLocaleTimeString()}]</span>
                  {log.text}
                </motion.div>
              ))}
            </AnimatePresence>
          )}
          <div ref={logsEndRef} />
        </div>
      </div>

      <footer className="h-12 bg-black/60 border-t border-white/10 flex items-center justify-between px-8 text-[10px] z-10 relative">
        <div className="flex gap-8">
          <div className="flex gap-2 items-center">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse"></span>
            <span className="uppercase tracking-tighter opacity-70 text-slate-300">Server: Centralized-Vault-01</span>
          </div>
          <div className="flex gap-2 items-center hidden sm:flex">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
            <span className="uppercase tracking-tighter opacity-70 text-slate-300">Device: Forensic-Pad-Alpha</span>
          </div>
        </div>
        <div className="font-mono opacity-40 text-slate-300">
          LATENCY: 12ms // PACKET_LOSS: 0% // CRYPTO_STR: ULTRA
        </div>
      </footer>
      
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(255, 255, 255, 0.02);
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.1);
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(34, 211, 238, 0.5);
        }
      `}</style>
    </div>
  );
}
