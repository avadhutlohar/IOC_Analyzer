import React from "react";

export default function BulkTable({ rows, onRowClick, expandedRow }) {
  const tools = ["abuseipdb", "virustotal", "shodan", "otx", "whois"];

  return (
    <div className="overflow-x-auto border-4 border-retro-dark-border shadow-retro">
      <table className="min-w-full border-collapse border-3 border-retro-dark-border bg-white dark:bg-gray-800">
        <thead>
          <tr className="bg-retro-terminal-amber">
            <th className="border-2 border-retro-dark-border px-3 py-2 text-left text-black font-bold">IOC</th>
            {tools.map((tool) => (
              <th
                key={tool}
                className="border-2 border-retro-dark-border px-3 py-2 text-left text-black font-bold"
              >
                {tool.toUpperCase()}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.ioc}
              onClick={() => onRowClick(row.ioc)}
              className={`cursor-pointer border-2 border-retro-dark-border hover:bg-custom-light-bg dark:hover:bg-custom-dark-gray hover:shadow-retro-inset ${
                 expandedRow === row.ioc ? "bg-custom-light-bg dark:bg-custom-dark-gray shadow-retro-inset" : ""
               }`}
            >
              <td className="border-2 border-retro-dark-border px-3 py-2 font-medium text-custom-dark-gray dark:text-custom-cream">
                {row.ioc}
              </td>
              {tools.map((tool) => {
                const cell = row.cells[tool];
                if (!cell) return (
                  <td key={tool} className="border-2 border-retro-dark-border px-3 py-2 text-custom-blue dark:text-custom-light-blue">
                    N/A
                  </td>
                );
                return (
                  <td key={tool} className="border-2 border-retro-dark-border px-3 py-2">
                    <div className="flex flex-col">
                      <span className="font-semibold text-custom-dark-gray dark:text-custom-cream">{cell.score_display}</span>
                      {cell.summary && <span className="text-sm text-custom-blue dark:text-custom-light-blue">{cell.summary}</span>}
                      {cell.link && (
                        <a
                          href={cell.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-custom-blue dark:text-custom-light-blue underline text-sm"
                          onClick={(e) => e.stopPropagation()}
                        >
                          Open
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
