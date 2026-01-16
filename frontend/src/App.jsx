import React, { useState } from "react";
import SingleIOCView from "./components/SingleIOCView.jsx";
import BulkIOCView from "./components/BulkIOCView.jsx";
import { ThemeProvider, useTheme } from "./contexts/ThemeContext.jsx";

function AppContent() {
  const [mode, setMode] = useState("single"); // "single" or "bulk"
  const { isDarkMode, toggleTheme } = useTheme();

  return (
    <div className={`min-h-screen transition-colors duration-200 ${
      isDarkMode ? 'bg-bg-primary text-text-primary' : 'bg-gray-100 text-gray-900'
    }`}>
      <div className="max-w-7xl mx-auto p-6">
        {/* Header with title and dark mode toggle */}
        <div className="flex justify-between items-center mb-8 border-b border-bg-tertiary pb-4">
          <div className="flex-1"></div>
          <h1 className="text-4xl font-bold text-center flex-1 text-accent-primary tracking-tight">IOC Analyzer</h1>
          <div className="flex-1 flex justify-end">
            <button
              onClick={toggleTheme}
              className={`p-2 rounded-full transition-colors ${
                isDarkMode 
                  ? 'bg-bg-secondary hover:bg-bg-tertiary text-text-primary' 
                  : 'bg-white hover:bg-gray-200 text-gray-800'
              }`}
              title={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {isDarkMode ? (
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                </svg>
              )}
            </button>
          </div>
        </div>

        {/* Mode Switch */}
        <div className="flex justify-center gap-4 mb-8">
          <button
            className={`px-6 py-2 rounded-lg font-medium transition-all duration-200 ${
              mode === "single" 
                ? "bg-accent-primary text-white shadow-lg shadow-accent-primary/20" 
                : isDarkMode 
                  ? "bg-bg-secondary text-text-secondary hover:bg-bg-tertiary hover:text-text-primary" 
                  : "bg-white text-gray-600 hover:bg-gray-100"
            }`}
            onClick={() => setMode("single")}
          >
            Single IOC
          </button>
          <button
            className={`px-6 py-2 rounded-lg font-medium transition-all duration-200 ${
              mode === "bulk" 
                ? "bg-accent-primary text-white shadow-lg shadow-accent-primary/20" 
                : isDarkMode 
                  ? "bg-bg-secondary text-text-secondary hover:bg-bg-tertiary hover:text-text-primary" 
                  : "bg-white text-gray-600 hover:bg-gray-100"
            }`}
            onClick={() => setMode("bulk")}
          >
            Bulk IOC
          </button>
        </div>

        {/* Render based on mode */}
        <div className={`rounded-xl p-6 ${isDarkMode ? 'bg-bg-secondary border border-bg-tertiary' : 'bg-white shadow-sm'}`}>
          {mode === "single" ? <SingleIOCView /> : <BulkIOCView />}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}
