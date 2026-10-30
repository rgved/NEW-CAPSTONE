import React, { useEffect, useState } from "react";
import { ShieldCheck, XCircle, Globe, Loader2, Copy, CheckCircle2 } from "lucide-react";
import { api } from "../services/api";

interface OwnershipModalProps {
  open: boolean;
  code: string;
  message: string;
  targetUrl: string;
  onClose: () => void;
  onUseDemo: () => void;
  onVerified: () => void;
}

interface Challenge {
  host: string;
  token: string;
  txt_record: string;
  file_url: string;
  challenge_expires_hours: number;
}

export default function OwnershipModal({ open, code, message, targetUrl, onClose, onUseDemo, onVerified }: OwnershipModalProps) {
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [method, setMethod] = useState<"file" | "dns">("file");
  const [busy, setBusy] = useState(false);
  const [flowError, setFlowError] = useState("");
  const [verified, setVerified] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      setChallenge(null);
      setMethod("file");
      setBusy(false);
      setFlowError("");
      setVerified(false);
      setCopied(false);
    }
  }, [open]);

  if (!open) return null;

  const startVerification = async () => {
    setBusy(true);
    setFlowError("");
    try {
      const res = await api.ownership.challenge(targetUrl);
      setChallenge(res);
    } catch (err: any) {
      setFlowError(err.message || "Could not start verification");
    } finally {
      setBusy(false);
    }
  };

  const confirmVerification = async () => {
    setBusy(true);
    setFlowError("");
    try {
      await api.ownership.verify(targetUrl, method);
      setVerified(true);
    } catch (err: any) {
      setFlowError(err.message || "Verification failed");
    } finally {
      setBusy(false);
    }
  };

  const copyToken = async () => {
    if (!challenge) return;
    try {
      await navigator.clipboard.writeText(challenge.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
import { ShieldCheck, XCircle, Globe, Loader2, Copy, CheckCircle2 } from "lucide-react";
import { api } from "../services/api";

interface OwnershipModalProps {
  open: boolean;
  code: string;
  message: string;
  targetUrl: string;
  onClose: () => void;
  onUseDemo: () => void;
  onVerified: () => void;
}

interface Challenge {
  host: string;
  token: string;
  txt_record: string;
  file_url: string;
  challenge_expires_hours: number;
}

export default function OwnershipModal({ open, code, message, targetUrl, onClose, onUseDemo, onVerified }: OwnershipModalProps) {
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [method, setMethod] = useState<"file" | "dns">("file");
  const [busy, setBusy] = useState(false);
  const [flowError, setFlowError] = useState("");
  const [verified, setVerified] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      setChallenge(null);
      setMethod("file");
      setBusy(false);
      setFlowError("");
      setVerified(false);
      setCopied(false);
    }
  }, [open]);

  if (!open) return null;

  const startVerification = async () => {
    setBusy(true);
    setFlowError("");
    try {
      const res = await api.ownership.challenge(targetUrl);
      setChallenge(res);
    } catch (err: any) {
      setFlowError(err.message || "Could not start verification");
    } finally {
      setBusy(false);
    }
  };

  const confirmVerification = async () => {
    setBusy(true);
    setFlowError("");
    try {
      await api.ownership.verify(targetUrl, method);
      setVerified(true);
    } catch (err: any) {
      setFlowError(err.message || "Verification failed");
    } finally {
      setBusy(false);
    }
  };

  const copyToken = async () => {
    if (!challenge) return;
    try {
      await navigator.clipboard.writeText(challenge.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="bg-[#141A23] border-2 border-black shadow-[6px_6px_0px_#000] max-w-xl w-full p-8 space-y-5 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-6 h-6 text-[#E2F952]" />
          <h2 className="text-lg font-bold text-[#F8FAFC]">
            {verified ? "Target verified" : "Ownership verification required"}
          </h2>
        </div>

        {!verified && (
          <p className="text-sm text-[#CBD5E1] leading-relaxed">
            {message || "Scans are limited to websites you own or control. Prove ownership of this target, or use the local demo target."}
          </p>
        )}

        {code === "AUTH_WEAK_IDENTITY" && !verified && (
          <p className="text-xs text-[#EF4444] flex items-center gap-1.5">
            <XCircle className="w-3.5 h-3.5" /> Google sign-in cannot authorize scans. Please sign in with a password account first.
          </p>
        )}

        {verified ? (
          <div className="space-y-5">
            <div className="bg-[#0E1217] border-2 border-black p-4 flex items-center gap-2 text-sm text-[#E2F952]">
              <CheckCircle2 className="w-4 h-4" /> Ownership verified for the next 30 days. You can scan this target now.
            </div>
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                onClick={onVerified}
                className="flex-1 px-5 py-3 bg-[#E2F952] text-black border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all cursor-pointer"
              >
                Start scan
              </button>
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-5 py-3 bg-[#0E1217] text-[#CBD5E1] border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        ) : challenge ? (
          <div className="space-y-4">
            <div className="bg-[#0E1217] border-2 border-black p-4 space-y-2">
              <span className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider">Your verification token</span>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs font-mono text-[#E2F952] break-all">{challenge.token}</code>
                <button
                  type="button"
                  onClick={copyToken}
                  className="px-2 py-1.5 bg-[#1C2533] border-2 border-black text-xs font-bold text-[#CBD5E1] flex items-center gap-1 cursor-pointer"
                >
                  <Copy className="w-3 h-3" /> {copied ? "Copied" : "Copy"}
                </button>
              </div>
            </div>

            <div className="space-y-2 text-xs text-[#94A3B8] leading-relaxed">
              <p className="font-bold text-[#F8FAFC]">Place this token on {challenge.host} using one method:</p>
              <label className="flex items-start gap-2 cursor-pointer">
                <input type="radio" checked={method === "file"} onChange={() => setMethod("file")} className="mt-0.5" />
                <span>
                  <span className="font-bold text-[#CBD5E1]">File:</span> serve the token (plain text) at
                  <span className="font-mono text-[#E2F952] block break-all">{challenge.file_url}</span>
                </span>
              </label>
              <label className="flex items-start gap-2 cursor-pointer">
                <input type="radio" checked={method === "dns"} onChange={() => setMethod("dns")} className="mt-0.5" />
                <span>
                  <span className="font-bold text-[#CBD5E1]">DNS:</span> add a TXT record
                  <span className="font-mono text-[#E2F952] block break-all">{challenge.txt_record}</span>
                  containing the token.
                </span>
              </label>
              <p>The challenge expires in {challenge.challenge_expires_hours} hours.</p>
            </div>

            {flowError && (
              <p className="text-xs text-[#EF4444] flex items-center gap-1.5">
                <XCircle className="w-3.5 h-3.5" /> {flowError}
              </p>
            )}

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                onClick={confirmVerification}
                disabled={busy}
                className="flex-1 px-5 py-3 bg-[#E2F952] text-black border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60"
              >
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />} Verify ownership
              </button>
              <button
                type="button"
                onClick={onUseDemo}
                className="flex-1 px-5 py-3 bg-[#0E1217] text-[#E2F952] border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <Globe className="w-4 h-4" /> Demo Details
              </button>
              <button
                type="button"
                onClick={onClose}
                className="px-5 py-3 bg-[#0E1217] text-[#CBD5E1] border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-[#0E1217] border-2 border-black p-4 text-xs text-[#94A3B8] leading-relaxed space-y-1.5">
              <p><span className="text-[#F8FAFC] font-bold">How it works:</span> we give you a unique token. You place it on the target (a file or DNS record), and we fetch it back to confirm you control the site. Verification lasts 30 days per domain.</p>
            </div>

            {flowError && (
              <p className="text-xs text-[#EF4444] flex items-center gap-1.5">
                <XCircle className="w-3.5 h-3.5" /> {flowError}
              </p>
            )}

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                onClick={startVerification}
                disabled={busy}
                className="flex-1 px-5 py-3 bg-[#E2F952] text-black border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60"
              >
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />} Verify this site
              </button>
              <button
                type="button"
                onClick={onUseDemo}
                className="flex-1 px-5 py-3 bg-[#0E1217] text-[#E2F952] border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <Globe className="w-4 h-4" /> Demo Details
              </button>
              <button
                type="button"
                onClick={onClose}
                className="px-5 py-3 bg-[#0E1217] text-[#CBD5E1] border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
