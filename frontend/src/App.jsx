import React, { useState } from "react";
import SingleIOCView from "./components/SingleIOCView.jsx";
import BulkIOCView from "./components/BulkIOCView.jsx";
import { ThemeProvider, useTheme } from "./contexts/ThemeContext.jsx";

function AppContent() {
  const [mode, setMode] = useState("single"); // "single" or "bulk"
  const { isDarkMode, toggleTheme } = useTheme();

  return (
    <div className={`min-h-screen transition-colors duration-200 border-4 border-retro-dark-border ${
      isDarkMode ? 'bg-custom-dark-gray text-custom-cream' : 'bg-custom-light-bg text-custom-dark-gray'
    }`}>
      <div className="max-w-auto mx-auto p-6 border-2 border-retro-dark-border m-2 shadow-retro">
        {/* Header with title and dark mode toggle */}
        <div className="flex justify-between items-center mb-6">
          <div className="flex-1"></div>
          <h1 className="text-3xl font-bold text-center flex-1 border-3 border-retro-dark-border p-2 shadow-retro bg-retro-terminal-amber text-black">IOC Analyzer</h1>
          <div className="flex-1 flex justify-end">
            <button
              onClick={toggleTheme}
              className={`p-2 border-2 border-retro-dark-border shadow-retro transition-colors ${
                isDarkMode 
                  ? 'bg-custom-gray hover:bg-custom-light-gray text-custom-cream' 
                  : 'bg-custom-light-gray hover:bg-custom-gray text-custom-dark-gray'
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
        <div className="grid grid-cols-2 gap-4 mb-6">
          <button
            className={`px-4 py-2 border-3 border-retro-dark-border shadow-retro transition-colors ${
              mode === "single" 
                ? "bg-custom-gray text-custom-cream" 
                : isDarkMode 
                  ? "bg-custom-light-gray text-custom-cream hover:bg-custom-gray" 
                  : "bg-custom-light-gray text-custom-dark-gray hover:bg-custom-gray hover:text-custom-cream"
            }`}
            onClick={() => setMode("single")}
          >
            Single IOC
          </button>
          <button
            className={`px-4 py-2 border-3 border-retro-dark-border shadow-retro transition-colors ${
              mode === "bulk" 
                ? "bg-custom-gray text-custom-cream" 
                : isDarkMode 
                  ? "bg-custom-light-gray text-custom-cream hover:bg-custom-gray" 
                  : "bg-custom-light-gray text-custom-dark-gray hover:bg-custom-gray hover:text-custom-cream"
            }`}
            onClick={() => setMode("bulk")}
          >
            Bulk IOC
          </button>
        </div>

        {/* Render based on mode */}
        {mode === "single" ? <SingleIOCView /> : <BulkIOCView />}
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
