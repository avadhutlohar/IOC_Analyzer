import React, { useState, useEffect } from 'react';

export default function ProgressBar({ isLoading, duration = 2000 }) {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (!isLoading) {
      if (progress > 0 && progress < 100) {
        setProgress(100);
        setTimeout(() => setProgress(0), 500); // Reset after completion
      }
      return;
    }

    setProgress(0);
    const interval = 50; // Update every 50ms
    const steps = duration / interval;
    const increment = 90 / steps; // Target 90% completion

    const timer = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) {
          clearInterval(timer);
          return 90;
        }
        return prev + increment;
      });
    }, interval);

    return () => clearInterval(timer);
  }, [isLoading, duration]);

  if (!isLoading && progress === 0) return null;

  return (
    <div className="w-full bg-bg-tertiary rounded-full h-2.5 mb-4 overflow-hidden">
      <div
        className="bg-accent-primary h-2.5 rounded-full transition-all duration-100 ease-out"
        style={{ width: `${progress}%` }}
      ></div>
      <div className="text-xs text-center mt-1 text-text-secondary">
        {progress < 100 ? 'Analyzing...' : 'Complete!'}
      </div>
    </div>
  );
}
