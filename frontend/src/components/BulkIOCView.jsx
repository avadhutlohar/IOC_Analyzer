import React, { useState } from "react";
import axios from "axios";
import BulkTable from "./BulkTable.jsx";
import Tabs from "./Tabs.jsx";
import ProgressBar from "./ProgressBar";
import { apiUrl } from "../config";
import * as XLSX from "xlsx";
import { saveAs } from "file-saver";

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

  const handleExportExcel = () => {
    if (!rows.length) return;

    // Flatten data for Excel
    const dataForExcel = rows.map(row => {
        const flatRow = { IOC: row.ioc };
        Object.keys(row.cells).forEach(tool => {
            const cell = row.cells[tool];
            flatRow[`${tool.toUpperCase()} Score`] = cell.score_display;
            flatRow[`${tool.toUpperCase()} Summary`] = cell.summary;
        });
        return flatRow;
    });

    const worksheet = XLSX.utils.json_to_sheet(dataForExcel);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "IOC Analysis");
    const excelBuffer = XLSX.write(workbook, { bookType: "xlsx", type: "array" });
    const data = new Blob([excelBuffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;charset=UTF-8" });
    saveAs(data, `ioc_analysis_${new Date().toISOString().slice(0, 10)}.xlsx`);
  };

  const handleExportTxt = () => {
    if (!rows.length) return;

    let txtContent = "IOC Analysis Report\n";
    txtContent += "===================\n\n";

    rows.forEach(row => {
        txtContent += `IOC: ${row.ioc}\n`;
        txtContent += `-------------------\n`;
        Object.keys(row.cells).forEach(tool => {
            const cell = row.cells[tool];
            txtContent += `${tool.toUpperCase()}:\n`;
            txtContent += `  Score: ${cell.score_display}\n`;
            if (cell.summary) txtContent += `  Summary: ${cell.summary}\n`;
        });
        txtContent += "\n";
    });

    const blob = new Blob([txtContent], { type: "text/plain;charset=utf-8" });
    saveAs(blob, `ioc_analysis_${new Date().toISOString().slice(0, 10)}.txt`);
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
        const res = await axios.post(apiUrl("/analyze/bulk"), {
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
      const res = await axios.get(apiUrl(`/analyze/${detectedType}/${encodeURIComponent(ioc)}`));
      setExpandedData(res.data.results);
    } catch (e) {
      console.error("Error loading expanded row", e);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      {/* Input section */}
      <div className="grid gap-6">
        <div className="flex flex-col gap-2">
          <label className="text-sm font-medium text-text-secondary">Upload File</label>
          <input
            type="file"
            accept=".txt,.csv"
            onChange={handleFileUpload}
            className="block w-full text-sm text-text-secondary
              file:mr-4 file:py-2 file:px-4
              file:rounded-full file:border-0
              file:text-sm file:font-semibold
              file:bg-accent-primary file:text-white
              hover:file:bg-accent-hover
              cursor-pointer"
          />
          <div className="text-xs text-text-muted space-y-1">
            <p>Supported: .txt, .csv (max 10MB)</p>
            <p>Format: One IOC per line</p>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <label className="text-sm font-medium text-text-secondary">Or Paste IOCs</label>
          <textarea
            rows={6}
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            placeholder="Enter IOCs here: One IOC per line..."
            className="w-full p-3 rounded-lg bg-bg-tertiary text-text-primary placeholder-text-muted border border-transparent focus:border-accent-primary focus:ring-1 focus:ring-accent-primary outline-none transition-all resize-y"
          />
        </div>

        <button
          onClick={analyzeBulk}
          className="w-full sm:w-auto px-6 py-3 rounded-lg bg-accent-primary hover:bg-accent-hover text-white font-medium transition-colors shadow-lg shadow-accent-primary/20"
        >
          Analyze Bulk
        </button>

        {rows.length > 0 && (
          <div className="flex gap-2 w-full sm:w-auto">
             <button
              onClick={handleExportExcel}
              className="flex-1 sm:flex-none px-4 py-3 rounded-lg bg-green-600 hover:bg-green-700 text-white font-medium transition-colors shadow-sm flex items-center justify-center gap-2"
              title="Export to Excel"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              XLSX
            </button>
            <button
              onClick={handleExportTxt}
              className="flex-1 sm:flex-none px-4 py-3 rounded-lg bg-gray-600 hover:bg-gray-700 text-white font-medium transition-colors shadow-sm flex items-center justify-center gap-2"
              title="Export to Text"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              TXT
            </button>
          </div>
        )}
      </div>

      {/* Progress Bar */}
      <ProgressBar isLoading={loading} duration={5000} />

      {/* Bulk Table */}
      {rows.length > 0 && (
        <BulkTable rows={rows} onRowClick={expandRow} expandedRow={expandedRow} />
      )}

      {/* Expanded row view */}
      {expandedData && (
        <div className="mt-8 p-6 rounded-xl bg-bg-tertiary border border-bg-primary/50">
          <h3 className="text-lg font-semibold mb-4 text-text-primary flex items-center gap-2">
            <span className="text-accent-secondary">Analysis:</span> {expandedRow}
          </h3>
          <Tabs results={expandedData} iocType={expandedIocType} ioc={expandedRow} />
        </div>
      )}
    </div>
  );
}
