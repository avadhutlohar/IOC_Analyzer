import React from "react";

export default function BulkTable({ rows, onRowClick, expandedRow }) {
  const tools = ["abuseipdb", "virustotal", "shodan", "otx", "whois"];

  return (
    <div className="overflow-x-auto rounded-xl border border-bg-tertiary shadow-lg">
      <table className="min-w-full border-collapse bg-bg-secondary">
        <thead>
          <tr className="bg-bg-tertiary border-b border-bg-primary">
            <th className="px-6 py-4 text-left text-xs font-semibold text-text-secondary uppercase tracking-wider">IOC</th>
            {tools.map((tool) => (
              <th
                key={tool}
                className="px-6 py-4 text-left text-xs font-semibold text-text-secondary uppercase tracking-wider"
              >
                {tool.toUpperCase()}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-bg-tertiary">
          {rows.map((row) => (
            <tr
              key={row.ioc}
              onClick={() => onRowClick(row.ioc)}
              className={`cursor-pointer transition-colors hover:bg-bg-tertiary/50 ${
                 expandedRow === row.ioc ? "bg-bg-tertiary/80" : ""
               }`}
            >
              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-text-primary">
                {row.ioc}
              </td>
              {tools.map((tool) => {
                const cell = row.cells[tool];
                if (!cell) return (
                  <td key={tool} className="px-6 py-4 whitespace-nowrap text-sm text-text-muted">
                    N/A
                  </td>
                );
                return (
                  <td key={tool} className="px-6 py-4 whitespace-nowrap text-sm">
                    <div className="flex flex-col">
                      <span className="font-medium text-text-primary">{cell.score_display}</span>
                      {cell.summary && <span className="text-xs text-text-secondary mt-0.5">{cell.summary}</span>}
                      {cell.link && (
                        <a
                          href={cell.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-accent-secondary hover:text-accent-primary hover:underline text-xs mt-1 inline-flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          Open ↗
                        </a>
                      )}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
