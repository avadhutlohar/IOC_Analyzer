import React, { useState } from "react";
import axios from "axios";
import Tabs from "./Tabs.jsx";

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
      const res = await axios.get(
        `http://localhost:8000/analyze/${detectedType}/${encodeURIComponent(ioc)}`
      );
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
    <div className="card bg-custom-light-bg dark:bg-custom-dark-gray border-4 border-retro-dark-border shadow-retro p-6">
      {/* Input Section */}
      <div className="flex gap-2 mb-6">
        <input
          type="text"
          placeholder="Enter IP, URL, domain, or hash "
          value={ioc}
          onChange={(e) => setIoc(e.target.value)}
          onKeyPress={handleKeyPress}
          className="border-3 border-retro-dark-border shadow-retro-inset p-2 flex-1 bg-custom-light-bg dark:bg-custom-dark-gray text-custom-dark-gray dark:text-custom-cream placeholder-custom-gray dark:placeholder-custom-light-gray focus:ring-2 focus:ring-retro-terminal-green focus:border-retro-terminal-green"
        />
        <button
          onClick={analyzeIOC}
          className="bg-custom-gray hover:bg-custom-light-gray text-custom-cream px-4 py-2 border-3 border-retro-dark-border shadow-retro transition-colors"
        >
          Analyze
        </button>
      </div>

      {loading && <p className="text-custom-gray dark:text-custom-light-gray">Loading...</p>}

      {/* Results */}
      {result && (
        <Tabs results={result.results} iocType={iocType} ioc={ioc} />
      )}
    </div>
  );
}
