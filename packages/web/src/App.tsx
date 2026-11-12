import * as crypto from "@messager/crypto";
import { useEffect, useState } from "react";

type CryptoStatus = "loading" | "ready" | "failed";

/** Placeholder screen: proves the app loads and the crypto library works in the browser. */
export function App() {
  const [status, setStatus] = useState<CryptoStatus>("loading");

  useEffect(() => {
    let cancelled = false;
    crypto.ready.then(
      () => {
        if (!cancelled) setStatus("ready");
      },
      () => {
        if (!cancelled) setStatus("failed");
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main>
      <h1>Messager</h1>
      <p>Prototype. No security review performed. Not for sensitive real-world use.</p>
      <p>Crypto library: {status}</p>
    </main>
  );
}
