"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, setToken } from "@/lib/api";
import { Shield } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@vigil.dev");
  const [password, setPassword] = useState("vigiladmin");
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { access_token, refresh_token } = await api.login(email, password);
      setToken(access_token, refresh_token);
      router.push("/");
    } catch {
      setError("Invalid credentials. Ensure the backend is running and seeded.");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <Shield className="h-8 w-8 text-accent" />
          <span className="text-2xl font-bold">VIGIL</span>
        </div>
        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="mb-1 block text-xs text-gray-400">Email</label>
            <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">Password</label>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button className="btn-primary w-full justify-center" type="submit">Sign in</button>
        </form>
        <p className="mt-4 text-center text-xs text-gray-600">
          Default: admin@vigil.dev / vigiladmin
        </p>
      </div>
    </div>
  );
}
