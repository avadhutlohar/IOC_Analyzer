import React, { useState } from "react";
import axios from "axios";
import Tabs from "./Tabs.jsx";
import ProgressBar from "./ProgressBar";
import { apiUrl } from "../config";

export default function SingleIOCView() {
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [iocType, setIocType] = useState(null);

  // Auto-detect IOC type based on input
  const detectIOCType = (input) => {
    const trimmed = input.trim();
    
    // IP address pattern (IPv4)
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipPattern.test(trimmed)) {
      return 'ip';
    }
    
    // URL pattern
    const urlPattern = /^https?:\/\/.+/i;
    if (urlPattern.test(trimmed)) {
      return 'url';
    }
    
    // Hash pattern (MD5, SHA1, SHA256)
    const hashPattern = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    if (hashPattern.test(trimmed)) {
      return 'hash';
    }
    
    // Default to domain for everything else
    return 'domain';
  };

  const analyzeIOC = async () => {
    if (!ioc) return;
    
    const detectedType = detectIOCType(ioc);
    setIocType(detectedType);
    setLoading(true);
    
    try {
      const res = await axios.get(apiUrl(`/analyze/${detectedType}/${encodeURIComponent(ioc)}`));
      setResult(res.data);
    } catch (e) {
      console.error("Error analyzing IOC", e);
    }
    setLoading(false);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      analyzeIOC();
    }
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <div className="flex gap-4">
        <input
          type="text"
          placeholder="Enter IP, URL, domain, or hash "
          value={ioc}
          onChange={(e) => setIoc(e.target.value)}
          onKeyPress={handleKeyPress}
          className="flex-1 p-3 rounded-lg bg-bg-tertiary text-text-primary placeholder-text-muted border border-transparent focus:border-accent-primary focus:ring-1 focus:ring-accent-primary outline-none transition-all"
        />
        <button
          onClick={analyzeIOC}
          className="px-6 py-3 rounded-lg bg-accent-primary hover:bg-accent-hover text-white font-medium transition-colors shadow-lg shadow-accent-primary/20"
        >
          Analyze
        </button>
      </div>

      <ProgressBar isLoading={loading} duration={2000} />

      {/* Results */}
      {result && (
        <div className="animate-fadeIn">
          <Tabs results={result.results} iocType={iocType} ioc={ioc} />
        </div>
      )}
    </div>
  );
}
