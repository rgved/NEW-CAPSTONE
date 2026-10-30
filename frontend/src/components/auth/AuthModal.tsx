import React, { useState, useEffect } from "react";
import { useAuth } from "../../context/AuthContext";
import { api } from "../../services/api";
import { X, Lock, Mail, User as UserIcon, AlertCircle, ArrowRight, ShieldCheck, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import GoogleIcon from "./GoogleIcon";

declare global {
  interface Window {
    google?: any;
  }
}

export default function AuthModal() {
  const { isAuthModalOpen, closeAuthModal, authModalMode, setAuthData } = useAuth();
  const navigate = useNavigate();

  const [mode, setMode] = useState<"login" | "signup">(authModalMode);
  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Google OAuth state
  const [googleClientId, setGoogleClientId] = useState<string>(
    () => (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || ""
  );

  // Sync mode with context when opening
  useEffect(() => {
    setMode(authModalMode);
    setError(null);
  }, [authModalMode, isAuthModalOpen]);

  // Fetch configured Google Client ID from backend
  useEffect(() => {
    if (isAuthModalOpen) {
      api.auth
        .getGoogleConfig()
        .then((res) => {
          if (res?.google_client_id) {
            setGoogleClientId(res.google_client_id);
          }
        })
        .catch(() => {});
    }
  }, [isAuthModalOpen]);

  if (!isAuthModalOpen) return null;

  const handleGoogleClick = () => {
    setError(null);
    const effectiveClientId = googleClientId || (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || "";

    if (window.google?.accounts?.id && googleClientId) {
      try {
        window.google.accounts.id.initialize({
          client_id: googleClientId,
          callback: async (response: any) => {
            if (response.credential) {
              setLoading(true);
              try {
                const res = await api.auth.googleAuth({
                  credential: response.credential,
                });
                if (res && res.token) {
                  setAuthData(res.token, res.user);
                  navigate("/dashboard");
                }
              } catch (err: any) {
                setError(err?.message || "Google authentication failed.");
              } finally {
                setLoading(false);
              }
            }
          },
        });
        window.google.accounts.id.prompt();
        return;
      } catch (err) {
        // Fall back to direct modal
      }
    }

    // Google sign-in requires the official GIS credential flow; there is no manual fallback.
    setError("Google sign-in is unavailable. Please try again or use your password account.");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "login") {
        if (!usernameOrEmail.trim() || !password) {
          setError("Please fill in all fields.");
          setLoading(false);
          return;
        }

        const res = await api.auth.login({
          username_or_email: usernameOrEmail.trim(),
          password,
        });

        if (res && res.token) {
          setAuthData(res.token, res.user);
          navigate("/dashboard");
        }
      } else {
        if (!username.trim() || !email.trim() || !password) {
          setError("Please fill in all required fields.");
          setLoading(false);
          return;
        }

        if (password.length < 6) {
          setError("Password must be at least 6 characters long.");
          setLoading(false);
          return;
        }

        if (password !== confirmPassword) {
          setError("Passwords do not match.");
          setLoading(false);
          return;
        }

        const res = await api.auth.signup({
          username: username.trim(),
          email: email.trim(),
          password,
        });

        if (res && res.token) {
          setAuthData(res.token, res.user);
          navigate("/dashboard");
        }
      }
    } catch (err: any) {
      setError(err?.message || "Authentication failed. Please verify your details.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs animate-fade-in">
      <div 
        className="relative w-full max-w-md bg-[#141A23] border-3 border-black rounded-2xl shadow-[6px_6px_0px_#000] overflow-hidden p-8"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          onClick={closeAuthModal}
          className="absolute top-5 right-5 p-1.5 rounded-lg bg-[#181F2A] border-2 border-black shadow-[1.5px_1.5px_0px_#000] text-[#94A3B8] hover:text-black hover:bg-[#EF4444] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 transition-all cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        {(
          /* Standard Auth Screen with Google Button */
          <div>
            {/* Header */}
            <div className="text-center mb-6">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#0D1117] border-2 border-black shadow-[2px_2px_0px_#000] text-[#E2F952] mb-3">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <h2 className="text-xl font-black text-[#F8FAFC]">
                {mode === "login" ? "Sign In to Sniff" : "Create Security Account"}
              </h2>
              <p className="text-xs text-[#94A3B8] mt-1 font-editorial italic">
                {mode === "login"
                  ? "Access your scan history and security reconnaissance missions"
                  : "Register your analyst profile to isolate and track your scans"}
              </p>
            </div>

            {/* Google Sign-in Button */}
            <button
              type="button"
              onClick={handleGoogleClick}
              disabled={loading}
              className="w-full py-2.5 px-4 mb-4 bg-[#181F2A] hover:bg-[#202938] border-2 border-black text-[#F8FAFC] font-bold rounded-xl flex items-center justify-center gap-3 text-sm shadow-[2.5px_2.5px_0px_#000] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[4px_4px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 transition cursor-pointer disabled:opacity-50"
            >
              <GoogleIcon className="w-4 h-4" />
              <span>{mode === "login" ? "Sign in with Google" : "Sign up with Google"}</span>
            </button>

            {/* Divider */}
            <div className="relative my-4">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t-2 border-black" />
              </div>
              <div className="relative flex justify-center text-[10px] uppercase font-mono font-bold">
                <span className="bg-[#141A23] px-2.5 text-[#94A3B8]">Or continue with credentials</span>
              </div>
            </div>

            {/* Mode Toggle Tabs */}
            <div className="flex p-1 mb-6 bg-[#0D1117] border-2 border-black rounded-xl">
              <button
                type="button"
                onClick={() => {
                  setMode("login");
                  setError(null);
                }}
                className={`flex-1 py-2 text-xs font-black rounded-lg transition cursor-pointer ${
                  mode === "login"
                    ? "bg-[#E2F952] text-black border-2 border-black shadow-[2px_2px_0px_#000]"
                    : "text-[#94A3B8] hover:text-[#F8FAFC]"
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode("signup");
                  setError(null);
                }}
                className={`flex-1 py-2 text-xs font-black rounded-lg transition cursor-pointer ${
                  mode === "signup"
                    ? "bg-[#E2F952] text-black border-2 border-black shadow-[2px_2px_0px_#000]"
                    : "text-[#94A3B8] hover:text-[#F8FAFC]"
                }`}
              >
                Create Account
              </button>
            </div>

            {/* Error Alert */}
            {error && (
              <div className="mb-4 p-3 rounded-lg bg-[#EF4444]/20 border-2 border-black shadow-[2px_2px_0px_#000] flex items-start gap-2.5 text-red-200 text-xs">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{error}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {mode === "login" ? (
                <div>
                  <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5">
                    Username or Email
                  </label>
                  <div className="relative">
                    <UserIcon className="absolute left-3.5 top-3 w-4 h-4 text-[#64748B]" />
                    <input
                      type="text"
                      required
                      value={usernameOrEmail}
                      onChange={(e) => setUsernameOrEmail(e.target.value)}
                      placeholder="e.g. security_lead or lead@recon.io"
                      className="w-full pl-10 pr-4 py-2.5 bg-[#0D1117] border-2 border-black rounded-xl text-sm text-[#F8FAFC] placeholder-[#475569] focus:outline-hidden focus:border-[#E2F952] focus:shadow-[2px_2px_0px_#000] transition"
                    />
                  </div>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5">
                      Analyst Username
                    </label>
                    <div className="relative">
                      <UserIcon className="absolute left-3.5 top-3 w-4 h-4 text-[#64748B]" />
                      <input
                        type="text"
                        required
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Choose a username (min 3 chars)"
                        className="w-full pl-10 pr-4 py-2.5 bg-[#0D1117] border-2 border-black rounded-xl text-sm text-[#F8FAFC] placeholder-[#475569] focus:outline-hidden focus:border-[#E2F952] focus:shadow-[2px_2px_0px_#000] transition"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5">
                      Email Address
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3.5 top-3 w-4 h-4 text-[#64748B]" />
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="analyst@domain.com"
                        className="w-full pl-10 pr-4 py-2.5 bg-[#0D1117] border-2 border-black rounded-xl text-sm text-[#F8FAFC] placeholder-[#475569] focus:outline-hidden focus:border-[#E2F952] focus:shadow-[2px_2px_0px_#000] transition"
                      />
                    </div>
                  </div>
                </>
              )}

              <div>
                <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-3 w-4 h-4 text-[#64748B]" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password (min 6 chars)"
                    className="w-full pl-10 pr-4 py-2.5 bg-[#0D1117] border-2 border-black rounded-xl text-sm text-[#F8FAFC] placeholder-[#475569] focus:outline-hidden focus:border-[#E2F952] focus:shadow-[2px_2px_0px_#000] transition"
                  />
                </div>
              </div>

              {mode === "signup" && (
                <div>
                  <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-3.5 top-3 w-4 h-4 text-[#64748B]" />
                    <input
                      type="password"
                      required
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Re-enter your password"
                      className="w-full pl-10 pr-4 py-2.5 bg-[#0D1117] border-2 border-black rounded-xl text-sm text-[#F8FAFC] placeholder-[#475569] focus:outline-hidden focus:border-[#E2F952] focus:shadow-[2px_2px_0px_#000] transition"
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-3 px-4 bg-[#E2F952] hover:bg-[#ECFD78] text-black font-black border-2 border-black shadow-[3px_3px_0px_#000] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 rounded-xl flex items-center justify-center gap-2 text-sm transition cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-black" />
                    <span>Processing...</span>
                  </>
                ) : (
                  <>
                    <span>{mode === "login" ? "Sign In" : "Register Account"}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="mt-6 text-center text-xs text-[#64748B]">
              {mode === "login" ? (
                <p>
                  Need an account?{" "}
                  <button
                    type="button"
                    onClick={() => {
                      setMode("signup");
                      setError(null);
                    }}
                    className="text-[#38BDF8] font-semibold hover:underline cursor-pointer"
                  >
                    Sign up
                  </button>
                </p>
              ) : (
                <p>
                  Already have an account?{" "}
                  <button
                    type="button"
                    onClick={() => {
                      setMode("login");
                      setError(null);
                    }}
                    className="text-[#38BDF8] font-semibold hover:underline cursor-pointer"
                  >
                    Sign in
                  </button>
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
