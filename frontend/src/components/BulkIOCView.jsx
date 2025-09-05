import React, { useState } from "react";
import axios from "axios";
import BulkTable from "./BulkTable.jsx";
import Tabs from "./Tabs.jsx";
import { API_BASE } from "../config";

export default function BulkIOCView() {
  const [textInput, setTextInput] = useState("");
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [expandedRow, setExpandedRow] = useState(null);
  const [expandedData, setExpandedData] = useState(null);
  const [expandedIocType, setExpandedIocType] = useState(null);

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

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target.result;
      let lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      if (file.name.endsWith(".csv")) {
        // assume first column contains IOCs
        lines = lines.map((line) => line.split(",")[0].trim());
      }
      setTextInput(lines.join("\n"));
    };
    reader.readAsText(file);
  };

  const analyzeBulk = async () => {
    const values = textInput
      .split(/\r?\n|,/)
      .map((v) => v.trim())
      .filter(Boolean);
    if (!values.length) return;

    setLoading(true);
    try {
      // Group IOCs by detected type
      const groupedIOCs = {};
      values.forEach(ioc => {
        const type = detectIOCType(ioc);
        if (!groupedIOCs[type]) {
          groupedIOCs[type] = [];
        }
        groupedIOCs[type].push(ioc);
      });

      // Analyze each group separately
      const allRows = [];
      for (const [type, iocs] of Object.entries(groupedIOCs)) {
        const res = await axios.post(`${API_BASE}/analyze/bulk`, {
          type: type,
          values: iocs,
        });
        allRows.push(...res.data.rows);
      }
      
      setRows(allRows);
    } catch (e) {
      console.error("Error in bulk analysis", e);
    }
    setLoading(false);
  };

  const expandRow = async (ioc) => {
    if (expandedRow === ioc) {
      setExpandedRow(null);
      setExpandedData(null);
      setExpandedIocType(null);
      return;
    }
    setExpandedRow(ioc);
    setLoading(true);
    try {
      const detectedType = detectIOCType(ioc);
      setExpandedIocType(detectedType);
      const res = await axios.get(
        `${API_BASE}/analyze/${detectedType}/${encodeURIComponent(ioc)}`
      );
      setExpandedData(res.data.results);
    } catch (e) {
      console.error("Error loading expanded row", e);
    }
    setLoading(false);
  };

  return (
    <div className="card bg-custom-light-bg dark:bg-custom-dark-gray border-4 border-retro-dark-border shadow-retro p-6">
      {/* Input section */}
      <div className="flex flex-col gap-4 mb-6">
        <div className="flex flex-col gap-2">
          <input
            type="file"
            accept=".txt,.csv"
            onChange={handleFileUpload}
            className="border-3 border-retro-dark-border shadow-retro p-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white file:mr-4 file:py-2 file:px-4 file:border-2 file:border-retro-dark-border file:text-sm file:font-semibold file:bg-retro-terminal-amber file:text-black hover:file:bg-retro-terminal-green dark:file:bg-gray-600 dark:file:text-gray-200"
          />
          <div className="text-sm text-gray-600 dark:text-gray-400">
            <p><strong>Supported file types:</strong> .txt, .csv (max 10MB)</p>
            <p><strong>File format:</strong> One IOC per line or comma-separated values</p>
            <p><strong>Supported IOCs:</strong> IP addresses, domains, URLs (http/https), file hashes (MD5/SHA1/SHA256)</p>
          </div>
        </div>

        <textarea
          rows={6}
          value={textInput}
          onChange={(e) => setTextInput(e.target.value)}
          placeholder="Enter IOCs here:\n• IP addresses: 192.168.1.1\n• Domains: example.com\n• URLs: https://example.com/path\n• Hashes: MD5/SHA1/SHA256\n\nSeparate multiple IOCs with commas or new lines"
          className="border-3 border-retro-dark-border shadow-retro-inset p-2 w-full bg-custom-light-bg dark:bg-custom-dark-gray text-custom-dark-gray dark:text-custom-cream placeholder-custom-gray dark:placeholder-custom-light-gray focus:ring-2 focus:ring-retro-terminal-green focus:border-retro-terminal-green"
        />

        <button
          onClick={analyzeBulk}
          className="bg-custom-gray hover:bg-custom-light-gray text-custom-cream px-4 py-2 border-3 border-retro-dark-border shadow-retro transition-colors"
        >
          Analyze Bulk
        </button>
      </div>

      {loading && <p className="text-custom-gray dark:text-custom-light-gray">Loading...</p>}

      {/* Bulk Table */}
      {rows.length > 0 && (
        <BulkTable rows={rows} onRowClick={expandRow} expandedRow={expandedRow} />
      )}

      {/* Expanded row view */}
      {expandedData && (
        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">
            Expanded view for {expandedRow}
          </h3>
          <Tabs results={expandedData} iocType={expandedIocType} ioc={expandedRow} />
        </div>
      )}
    </div>
  );
}
