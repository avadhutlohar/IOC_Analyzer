import React, { useState } from "react";

export default function Tabs({ results, iocType, ioc }) {
  const [activeTab, setActiveTab] = useState("overview");

  // Generate external tool links
  const getToolLinks = () => {
    const encodeIOC = (value) => encodeURIComponent(value);
    
    const vtMap = {
      "ip": `https://www.virustotal.com/gui/ip-address/${encodeIOC(ioc)}`,
      "domain": `https://www.virustotal.com/gui/domain/${encodeIOC(ioc)}`,
      "hash": `https://www.virustotal.com/gui/file/${encodeIOC(ioc)}`,
      "url": `https://www.virustotal.com/gui/search/${encodeIOC(ioc)}`,
    };
    
    const links = {
      "virustotal": vtMap[iocType] || `https://www.virustotal.com/gui/search/${encodeIOC(ioc)}`,
      "otx": `https://otx.alienvault.com/indicator/${iocType}/${encodeIOC(ioc)}`,
    };
    
    if (iocType === "ip") {
      links.abuseipdb = `https://www.abuseipdb.com/check/${encodeIOC(ioc)}`;
      links.shodan = `https://www.shodan.io/host/${encodeIOC(ioc)}`;
    }
    
    if (iocType === "domain" || iocType === "url") {
      const domain = iocType === 'domain' ? ioc : ioc.split('//',1)[1]?.split('/')[0] || ioc;
      links.whois = `https://lookup.icann.org/en/lookup?name=${encodeIOC(domain)}`;
    }
    
    return links;
  };
  
  const toolLinks = getToolLinks();

  // Get available tabs based on IOC type
  const getAvailableTabs = () => {
    const tabs = ["overview"];
    
    switch (iocType) {
      case "ip":
        if (results.abuseipdb) tabs.push("abuseipdb");
        if (results.otx) tabs.push("otx");
        if (results.shodan) tabs.push("shodan");
        if (results.virustotal) tabs.push("virustotal");
        if (results.whois) tabs.push("whois");
        break;
      case "domain":
        if (results.otx) tabs.push("otx");
        if (results.virustotal) tabs.push("virustotal");
        if (results.whois) tabs.push("whois");
        break;
      case "url":
        if (results.otx) tabs.push("otx");
        if (results.virustotal) tabs.push("virustotal");
        if (results.whois) tabs.push("whois");
        break;
      case "hash":
        if (results.otx) tabs.push("otx");
        if (results.virustotal) tabs.push("virustotal");
        break;
      default:
        // Fallback to show all available tabs
        Object.keys(results).forEach(tool => {
          if (!tabs.includes(tool)) tabs.push(tool);
        });
    }
    
    return tabs;
  };

  // Render IOC-specific overview
  const renderOverview = () => {
    switch (iocType) {
      case "ip":
        return renderIPOverview();
      case "domain":
        return renderDomainOverview();
      case "url":
        return renderURLOverview();
      case "hash":
        return renderHashOverview();
      default:
        return renderDefaultOverview();
    }
  };

  const renderIPOverview = () => (
    <div>
      <ul className="list-disc ml-6 space-y-1">
        {results.abuseipdb && !results.abuseipdb.error && results.abuseipdb.data && (
          <li>AbuseIPDB Score: {results.abuseipdb.data.abuseConfidenceScore || 'N/A'}% 
            <a href={toolLinks.abuseipdb} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.abuseipdb?.error && (
          <li className="text-accent-primary dark:text-accent-secondary">AbuseIPDB: {typeof results.abuseipdb.error === 'object' ? (results.abuseipdb.error.message || JSON.stringify(results.abuseipdb.error)) : results.abuseipdb.error}</li>
        )}
        
        {results.otx && !results.otx.error && results.otx.pulse_info && (
          <li>OTX Pulses: {results.otx.pulse_info.count || 'N/A'} 
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.otx?.error && (
          <li className="text-red-600 dark:text-red-400">OTX: {typeof results.otx.error === 'object' ? (results.otx.error.message || JSON.stringify(results.otx.error)) : results.otx.error}</li>
        )}
        
        {results.shodan && !results.shodan.error && results.shodan.asn && (
          <li>Shodan ASN: {results.shodan.asn} 
            <a href={toolLinks.shodan} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.shodan?.error && (
          <li className="text-red-600">Shodan: {typeof results.shodan.error === 'object' ? (results.shodan.error.message || JSON.stringify(results.shodan.error)) : results.shodan.error}</li>
        )}
        
        {results.virustotal && !results.virustotal.error && results.virustotal.data?.attributes && (
          <li>
            VirusTotal Reputation: {(() => {
              const stats = results.virustotal.data.attributes.last_analysis_stats || {};
              const malicious = stats.malicious || 0;
              const total = Object.values(stats).reduce((sum, count) => sum + (count || 0), 0);
              return `${malicious}/${total}`;
            })()} 
            {results.virustotal.data.attributes.crowdsourced_context?.length > 0 && (
              <span className="text-red-600 font-semibold"> ⚠️ Threat alerts detected</span>
            )}
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
        
        {results.whois && !results.whois.error && (
          <li>
            WHOIS ASN: {results.whois.asn || "N/A"} | Country:{" "}
            {results.whois.asn_country_code || "N/A"}
            <a href={toolLinks.whois} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.whois?.error && (
          <li className="text-red-600">WHOIS: {typeof results.whois.error === 'object' ? (results.whois.error.message || JSON.stringify(results.whois.error)) : results.whois.error}</li>
        )}
      </ul>
    </div>
  );

  const renderDomainOverview = () => (
    <div>
      <ul className="list-disc ml-6 space-y-1">
        {results.otx && !results.otx.error && results.otx.pulse_info && (
          <li>OTX Pulses: {results.otx.pulse_info.count || 'N/A'} 
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.otx?.error && (
          <li className="text-red-600">OTX: {typeof results.otx.error === 'object' ? (results.otx.error.message || JSON.stringify(results.otx.error)) : results.otx.error}</li>
        )}
        
        {results.virustotal && !results.virustotal.error && results.virustotal.data?.attributes && (
          <li>
            VirusTotal Reputation: {(() => {
              const stats = results.virustotal.data.attributes.last_analysis_stats || {};
              const malicious = stats.malicious || 0;
              const total = Object.values(stats).reduce((sum, count) => sum + (count || 0), 0);
              return `${malicious}/${total}`;
            })()} 
            {results.virustotal.data.attributes.crowdsourced_context?.length > 0 && (
              <span className="text-red-600 font-semibold"> ⚠️ Threat alerts detected</span>
            )}
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
        
        {results.whois && !results.whois.error && (
          <li>
            WHOIS Org: {results.whois.org || "N/A"} | Country: {results.whois.country || "N/A"}
            <a href={toolLinks.whois} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.whois?.error && (
          <li className="text-red-600">WHOIS: {typeof results.whois.error === 'object' ? (results.whois.error.message || JSON.stringify(results.whois.error)) : results.whois.error}</li>
        )}
      </ul>
    </div>
  );

  const renderURLOverview = () => (
    <div>
      <ul className="list-disc ml-6 space-y-1">
        {results.otx && !results.otx.error && results.otx.pulse_info && (
          <li>OTX Pulses: {results.otx.pulse_info.count || 'N/A'} 
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.otx?.error && (
          <li className="text-red-600">OTX: {typeof results.otx.error === 'object' ? (results.otx.error.message || JSON.stringify(results.otx.error)) : results.otx.error}</li>
        )}
        
        {results.virustotal && !results.virustotal.error && results.virustotal.data?.attributes && (
          <li>
            VirusTotal Reputation: {(() => {
              const stats = results.virustotal.data.attributes.last_analysis_stats || {};
              const malicious = stats.malicious || 0;
              const total = Object.values(stats).reduce((sum, count) => sum + (count || 0), 0);
              return `${malicious}/${total}`;
            })()} 
            {results.virustotal.data.attributes.crowdsourced_context?.length > 0 && (
              <span className="text-red-600 font-semibold"> ⚠️ Threat alerts detected</span>
            )}
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
        
        {results.whois && !results.whois.error && (
          <li>
            WHOIS Org: {results.whois.org || "N/A"} | Country: {results.whois.country || "N/A"}
            <a href={toolLinks.whois} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.whois?.error && (
          <li className="text-red-600">WHOIS: {typeof results.whois.error === 'object' ? (results.whois.error.message || JSON.stringify(results.whois.error)) : results.whois.error}</li>
        )}
      </ul>
    </div>
  );

  const renderHashOverview = () => (
    <div>
      <ul className="list-disc ml-6 space-y-1">
        {results.otx && !results.otx.error && results.otx.pulse_info && (
          <li>OTX Pulses: {results.otx.pulse_info.count || 'N/A'} 
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.otx?.error && (
          <li className="text-red-600">OTX: {typeof results.otx.error === 'object' ? (results.otx.error.message || JSON.stringify(results.otx.error)) : results.otx.error}</li>
        )}
        
        {results.virustotal && !results.virustotal.error && results.virustotal.data?.attributes && (
          <li>
            VirusTotal Reputation: {(() => {
              const stats = results.virustotal.data.attributes.last_analysis_stats || {};
              const malicious = stats.malicious || 0;
              const total = Object.values(stats).reduce((sum, count) => sum + (count || 0), 0);
              return `${malicious}/${total}`;
            })()} 
            {results.virustotal.data.attributes.crowdsourced_context?.length > 0 && (
              <span className="text-red-600 font-semibold"> ⚠️ Threat alerts detected</span>
            )}
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-primary dark:text-accent-secondary hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
      </ul>
    </div>
  );

  const renderDefaultOverview = () => (
    <ul className="list-disc ml-6 space-y-1">
      {results.abuseipdb && !results.abuseipdb.error && results.abuseipdb.data && (
        <li>AbuseIPDB Score: {results.abuseipdb.data.abuseConfidenceScore || 'N/A'}</li>
      )}
      {results.abuseipdb?.error && (
        <li className="text-red-600">AbuseIPDB: {typeof results.abuseipdb.error === 'object' ? (results.abuseipdb.error.message || JSON.stringify(results.abuseipdb.error)) : results.abuseipdb.error}</li>
      )}
      
      {results.otx && !results.otx.error && results.otx.pulse_info && (
        <li>OTX Pulses: {results.otx.pulse_info.count || 'N/A'}</li>
      )}
      {results.otx?.error && (
        <li className="text-red-600">OTX: {typeof results.otx.error === 'object' ? (results.otx.error.message || JSON.stringify(results.otx.error)) : results.otx.error}</li>
      )}
      
      {results.shodan && !results.shodan.error && results.shodan.asn && (
        <li>Shodan ASN: {results.shodan.asn}</li>
      )}
      {results.shodan?.error && (
        <li className="text-red-600">Shodan: {typeof results.shodan.error === 'object' ? (results.shodan.error.message || JSON.stringify(results.shodan.error)) : results.shodan.error}</li>
      )}
      
      {results.virustotal && !results.virustotal.error && results.virustotal.data?.attributes && (
        <li>
          VT Analysis: {(() => {
            const stats = results.virustotal.data.attributes.last_analysis_stats || {};
            const malicious = stats.malicious || 0;
            const total = (stats.malicious || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
            return `${malicious}/${total}`;
          })()} 
          {results.virustotal.data.attributes.crowdsourced_context?.length > 0 && (
            <span className="text-red-600 font-semibold"> ⚠️ Threat alerts detected</span>
          )}
        </li>
      )}
      {results.virustotal?.error && (
        <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
      )}
      
      {results.whois && !results.whois.error && (
        <li>
          WHOIS ASN: {results.whois.asn || "N/A"} | Country:{" "}
          {results.whois.asn_country_code || "N/A"}
        </li>
      )}
      {results.whois?.error && (
        <li className="text-red-600">WHOIS: {typeof results.whois.error === 'object' ? (results.whois.error.message || JSON.stringify(results.whois.error)) : results.whois.error}</li>
      )}
    </ul>
  );

  // Render tool-specific tabs based on IOC type
  const renderToolTab = (tool, data) => {
    if (!data) return <p>No data available.</p>;
    
    // Handle error cases
    if (data.error) {
      const errorMessage = typeof data.error === 'object' 
        ? (data.error.message || JSON.stringify(data.error))
        : data.error;
      return (
        <div className="text-red-600 p-4 bg-red-50">
          <p><strong>Error:</strong> {errorMessage}</p>
        </div>
      );
    }

    switch (tool) {
      case "abuseipdb":
        return renderAbuseIPDBTab(data);
      case "otx":
        return renderOTXTab(data);
      case "shodan":
        return renderShodanTab(data);
      case "virustotal":
        return renderVirusTotalTab(data);
      case "whois":
        return renderWhoisTab(data);
      default:
        return <p>No structured view available.</p>;
    }
  };

  const renderAbuseIPDBTab = (data) => (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-accent-secondary font-semibold mb-2">Score Analysis</h4>
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between">
              <span className="text-text-secondary">Confidence Score:</span>
              <span className={`font-bold ${data.data?.abuseConfidenceScore > 50 ? 'text-status-error' : 'text-status-success'}`}>
                {data.data?.abuseConfidenceScore || 'N/A'}%
              </span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Total Reports:</span>
              <span className="text-text-primary">{data.data?.totalReports || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Last Reported:</span>
              <span className="text-text-primary">{data.data?.lastReportedAt ? new Date(data.data.lastReportedAt).toLocaleString() : 'N/A'}</span>
            </li>
          </ul>
        </div>
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-accent-secondary font-semibold mb-2">Infrastructure</h4>
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between">
              <span className="text-text-secondary">ISP:</span>
              <span className="text-text-primary">{data.data?.isp || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Usage Type:</span>
              <span className="text-text-primary">{data.data?.usageType || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Domain:</span>
              <span className="text-text-primary">{data.data?.domain || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Country:</span>
              <span className="text-text-primary">{data.data?.countryCode || 'N/A'}</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );

  const renderOTXTab = (data) => {
    if (iocType === "hash") {
      return (
        <div className="space-y-4">
          <ul className="list-disc ml-6 space-y-1">
            <li>Analysis Date: {data.analysis?.analysis?.datetime_int || 'N/A'}</li>
            <li>File Score: {data.analysis?.analysis?.plugins?.cuckoo?.result?.info?.combined_score || 'N/A'}</li>
            <li>Antivirus Detections: {data.analysis?.analysis?.plugins ? Object.entries(data.analysis.analysis.plugins).filter(([key, plugin]) => plugin.results && (plugin.results.detection || plugin.results.alerts)).map(([name, plugin]) => `${name.toUpperCase()}: ${plugin.results.detection || plugin.results.alerts?.[0] || 'Clean'}`).join(', ') : 'N/A'}</li>
            <li>Yara Detections: {data.analysis?.analysis?.plugins?.yara?.results?.length || 0} rules matched</li>
            <li>Pulse Count: {data.pulse_info?.count || 'N/A'}</li>
          </ul>
          
          {data.pulse_info?.pulses && data.pulse_info.pulses.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Related Pulses:</h4>
              <div className="space-y-2">
                {data.pulse_info.pulses.slice(0, 5).map((pulse, index) => (
                  <div key={index} className="bg-custom-light-gray dark:bg-bg-secondary border p-3">
                    <div className="font-medium">
                      <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-accent-primary dark:text-accent-secondary hover:underline">
                        {pulse.name}
                      </a>
                    </div>
                    {pulse.description && (
                      <div className="text-sm text-custom-gray dark:text-custom-light-gray mt-1">{pulse.description.substring(0, 200)}...</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {data.malware && data.malware.data && data.malware.data.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Malware Families:</h4>
              <div className="space-y-1">
                {data.malware.data.slice(0, 5).map((malware, index) => (
                  <div key={index} className="bg-red-50 dark:bg-red-900 border border-red-200 dark:border-red-700 p-2">
                    <span className="font-medium text-red-800">{malware.detections?.avast || malware.hash}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    } else if (iocType === "url") {
      // URL-specific OTX display
      const pulseCount = data.pulse_info?.count || 0;
      const verdict = pulseCount > 0 ? 'Suspicious' : 'Clean';
      const verdictColor = pulseCount > 0 ? 'text-red-600' : 'text-green-600';
      
      return (
        <div className="space-y-4">
          <ul className="list-disc ml-6 space-y-1">
            <li>Verdict: <span className={verdictColor}>{verdict}</span></li>
            <li>Indicator: {data.indicator || 'N/A'}</li>
            <li>Type: {data.type_title || data.type || 'N/A'}</li>
            {data.domain && <li>Domain: {data.domain}</li>}
            {data.hostname && <li>Domain: {data.hostname}</li>}
            {data.ip && <li>IP Address: {data.ip}</li>}
            {data.country_name && <li>Location: {data.country_name} ({data.country_code2 || 'N/A'})</li>}
            {data.asn && <li>ASN: {data.asn}</li>}
            {data.nameservers && data.nameservers.length > 0 && (
              <li>Nameservers: {data.nameservers.join(', ')}</li>
            )}
            {data.whois && <li>WHOIS: <a href={data.whois} target="_blank" rel="noopener noreferrer" className="text-accent-primary dark:text-accent-secondary hover:underline">Available</a></li>}
            {data.alexa && <li>Alexa Info: <a href={data.alexa} target="_blank" rel="noopener noreferrer" className="text-accent-primary dark:text-accent-secondary hover:underline">Available</a></li>}
            <li>Pulse Count: <span className={pulseCount > 0 ? 'text-red-600 font-semibold' : 'text-green-600'}>{pulseCount}</span></li>
          </ul>
          
          {data.pulse_info?.pulses && data.pulse_info.pulses.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Pulses:</h4>
              <div className="space-y-2">
                {data.pulse_info.pulses.slice(0, 5).map((pulse, index) => (
                  <div key={index} className="bg-gray-50 border p-3">
                    <div className="font-medium">
                      <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-accent-primary dark:text-accent-secondary hover:underline">
                        {pulse.name}
                      </a>
                    </div>
                    {pulse.description && (
                      <div className="text-sm text-gray-600 mt-1">{pulse.description.substring(0, 200)}...</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {data.malware && data.malware.data && data.malware.data.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Malware Families:</h4>
              <div className="space-y-1">
                {data.malware.data.slice(0, 5).map((malware, index) => (
                  <div key={index} className="bg-red-50 border border-red-200 p-2">
                    <span className="font-medium text-red-800">{malware.detections?.avast || malware.hash}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    } else if (iocType === "domain") {
      // Domain-specific OTX display
      const pulseCount = data.pulse_info?.count || 0;
      const verdict = pulseCount > 0 ? 'Suspicious' : 'Clean';
      const verdictColor = pulseCount > 0 ? 'text-red-600' : 'text-green-600';
      
      return (
        <div className="space-y-4">
          <ul className="list-disc ml-6 space-y-1">
            <li>Verdict: <span className={verdictColor}>{verdict}</span></li>
            <li>Indicator: {data.indicator || 'N/A'}</li>
            <li>Type: {data.type_title || data.type || 'N/A'}</li>
            {data.whois && <li>WHOIS: <a href={data.whois} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Available</a></li>}
            {data.alexa && <li>Alexa Info: <a href={data.alexa} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Available</a></li>}
            <li>Pulse Count: <span className={pulseCount > 0 ? 'text-red-600 font-semibold' : 'text-green-600'}>{pulseCount}</span></li>
          </ul>
          
          {data.pulse_info?.pulses && data.pulse_info.pulses.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Related Pulses:</h4>
              <div className="space-y-2">
                {data.pulse_info.pulses.slice(0, 5).map((pulse, index) => (
                  <div key={index} className="bg-gray-50 border p-3">
                    <div className="font-medium">
                      <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                        {pulse.name}
                      </a>
                    </div>
                    {pulse.description && (
                      <div className="text-sm text-gray-600 mt-1">{pulse.description.substring(0, 200)}...</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {data.malware && data.malware.data && data.malware.data.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Malware Families:</h4>
              <div className="space-y-1">
                {data.malware.data.slice(0, 5).map((malware, index) => (
                  <div key={index} className="bg-red-50 border border-red-200 p-2">
                    <span className="font-medium text-red-800">{malware.detections?.avast || malware.hash}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    } else {
      // IP-specific OTX display
      return (
        <ul className="list-disc ml-6 space-y-1">
          <li>Country: {typeof data.country_name === 'object' ? JSON.stringify(data.country_name) : (data.country_name || 'N/A')} ({typeof data.country_code2 === 'object' ? JSON.stringify(data.country_code2) : (data.country_code2 || 'N/A')})</li>
          <li>ASN: {typeof data.asn === 'object' ? JSON.stringify(data.asn) : (data.asn || 'N/A')}</li>
          <li>Reputation: {typeof data.reputation === 'object' ? JSON.stringify(data.reputation) : (data.reputation !== undefined ? data.reputation : 'N/A')}</li>
          <li>Validation Status: {Array.isArray(data.validation) ? data.validation.map(v => v?.name || v).join(', ') : (typeof data.validation === 'object' ? JSON.stringify(data.validation) : (data.validation || 'N/A'))}</li>
          <li>False Positive Reports: {Array.isArray(data.false_positive) ? data.false_positive.length : (typeof data.false_positive === 'object' ? JSON.stringify(data.false_positive) : (data.false_positive || 0))}</li>
        </ul>
      );
    }
  };

  const renderShodanTab = (data) => (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-accent-secondary font-semibold mb-2">Network Info</h4>
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between">
              <span className="text-text-secondary">ASN:</span>
              <span className="text-text-primary">{data.asn || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">ISP:</span>
              <span className="text-text-primary">{data.isp || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Organization:</span>
              <span className="text-text-primary">{data.org || 'N/A'}</span>
            </li>
             <li className="flex justify-between">
              <span className="text-text-secondary">Last Update:</span>
              <span className="text-text-primary">{data.last_update ? new Date(data.last_update).toLocaleDateString() : 'N/A'}</span>
            </li>
          </ul>
        </div>
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-accent-secondary font-semibold mb-2">System Info</h4>
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between">
              <span className="text-text-secondary">OS:</span>
              <span className="text-text-primary">{data.os || 'N/A'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Open Ports:</span>
              <span className="text-text-primary">{data.ports?.join(", ") || 'None'}</span>
            </li>
            <li className="flex justify-between">
              <span className="text-text-secondary">Hostnames:</span>
              <span className="text-text-primary truncate max-w-[200px]" title={data.hostnames?.join(", ")}>{data.hostnames?.length ? data.hostnames[0] : 'N/A'}</span>
            </li>
          </ul>
        </div>
      </div>
      
      {data.vulns && data.vulns.length > 0 && (
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-status-error font-semibold mb-2">Vulnerabilities ({data.vulns.length})</h4>
          <div className="flex flex-wrap gap-2">
            {data.vulns.slice(0, 10).map(vuln => (
              <span key={vuln} className="px-2 py-1 bg-status-error/10 text-status-error text-xs rounded border border-status-error/20">
                {vuln}
              </span>
            ))}
            {data.vulns.length > 10 && <span className="text-xs text-text-muted self-center">+{data.vulns.length - 10} more</span>}
          </div>
        </div>
      )}
      
      {data.tags && data.tags.length > 0 && (
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-accent-secondary font-semibold mb-2">Tags</h4>
          <div className="flex flex-wrap gap-2">
            {data.tags.map(tag => (
              <span key={tag} className="px-2 py-1 bg-accent-primary/10 text-accent-primary text-xs rounded border border-accent-primary/20">
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderVirusTotalTab = (data) => {
    const attr = data.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const reputation = attr.reputation || 0;
    const reputationText = reputation > 0 ? `${reputation} (Good)` : reputation < 0 ? `${reputation} (Bad)` : `${reputation} (Neutral)`;
    const crowdsourcedContext = attr.crowdsourced_context || [];
    
    // Common Stats Component
    const StatsDisplay = () => (
      <div className="bg-bg-tertiary p-4 rounded-lg mb-4">
        <h4 className="text-accent-secondary font-semibold mb-3">Detection Summary</h4>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center">
          <div className="p-2 bg-status-success/10 rounded border border-status-success/20">
            <div className="text-lg font-bold text-status-success">{stats.harmless || 0}</div>
            <div className="text-xs text-text-secondary">Harmless</div>
          </div>
          <div className="p-2 bg-status-error/10 rounded border border-status-error/20">
            <div className="text-lg font-bold text-status-error">{stats.malicious || 0}</div>
            <div className="text-xs text-text-secondary">Malicious</div>
          </div>
          <div className="p-2 bg-status-warning/10 rounded border border-status-warning/20">
            <div className="text-lg font-bold text-status-warning">{stats.suspicious || 0}</div>
            <div className="text-xs text-text-secondary">Suspicious</div>
          </div>
          <div className="p-2 bg-bg-secondary rounded border border-bg-primary">
            <div className="text-lg font-bold text-text-muted">{stats.undetected || 0}</div>
            <div className="text-xs text-text-secondary">Undetected</div>
          </div>
           <div className="p-2 bg-bg-secondary rounded border border-bg-primary">
            <div className="text-lg font-bold text-text-muted">{stats.timeout || 0}</div>
            <div className="text-xs text-text-secondary">Timeout</div>
          </div>
        </div>
      </div>
    );

    if (iocType === "hash") {
      const lastAnalysisDate = attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleString() : 'N/A';
      const firstSubmissionDate = attr.first_submission_date ? new Date(attr.first_submission_date * 1000).toLocaleString() : 'N/A';
      
      return (
        <div className="space-y-4">
          <StatsDisplay />
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">File Details</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between"><span className="text-text-secondary">Type:</span> <span className="text-text-primary">{attr.type_description || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Size:</span> <span className="text-text-primary">{attr.size ? `${(attr.size / 1024).toFixed(2)} KB` : 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Magic:</span> <span className="text-text-primary truncate max-w-[150px]" title={attr.magic}>{attr.magic || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Reputation:</span> <span className={reputation < 0 ? 'text-status-error' : 'text-status-success'}>{reputationText}</span></li>
              </ul>
            </div>
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">History</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between"><span className="text-text-secondary">First Seen:</span> <span className="text-text-primary">{firstSubmissionDate}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Last Analysis:</span> <span className="text-text-primary">{lastAnalysisDate}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Times Submitted:</span> <span className="text-text-primary">{attr.times_submitted || 'N/A'}</span></li>
              </ul>
            </div>
          </div>

          {attr.names && attr.names.length > 0 && (
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Known Filenames</h4>
              <div className="flex flex-wrap gap-2">
                {attr.names.slice(0, 5).map((name, i) => (
                  <span key={i} className="px-2 py-1 bg-bg-secondary text-text-secondary text-xs rounded border border-bg-primary font-mono">{name}</span>
                ))}
                {attr.names.length > 5 && <span className="text-xs text-text-muted self-center">+{attr.names.length - 5} more</span>}
              </div>
            </div>
          )}
        </div>
      );
    } else if (iocType === "url") {
       const creationDate = attr.creation_date ? new Date(attr.creation_date * 1000).toLocaleDateString() : 'N/A';
       const lastAnalysisDate = attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleDateString() : 'N/A';

       return (
        <div className="space-y-4">
          <StatsDisplay />
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Page Info</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between"><span className="text-text-secondary">Title:</span> <span className="text-text-primary truncate max-w-[200px]" title={attr.title}>{attr.title || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Response Code:</span> <span className="text-text-primary">{attr.last_http_response_code || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Threat Names:</span> <span className="text-status-error">{attr.threat_names?.join(", ") || 'None'}</span></li>
              </ul>
            </div>
             <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Context</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between"><span className="text-text-secondary">Creation Date:</span> <span className="text-text-primary">{creationDate}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Last Analysis:</span> <span className="text-text-primary">{lastAnalysisDate}</span></li>
                 <li className="flex justify-between"><span className="text-text-secondary">Reputation:</span> <span className={reputation < 0 ? 'text-status-error' : 'text-status-success'}>{reputationText}</span></li>
              </ul>
            </div>
          </div>
          
          {attr.categories && Object.keys(attr.categories).length > 0 && (
             <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Categories</h4>
              <div className="flex flex-wrap gap-2">
                {Object.values(attr.categories).slice(0, 8).map((cat, i) => (
                  <span key={i} className="px-2 py-1 bg-accent-primary/10 text-accent-primary text-xs rounded border border-accent-primary/20">{cat}</span>
                ))}
              </div>
            </div>
          )}
        </div>
       );
    } else {
      // IP-specific VirusTotal display
      return (
        <div className="space-y-4">
           <StatsDisplay />
           
           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
             <div className="bg-bg-tertiary p-4 rounded-lg">
               <h4 className="text-accent-secondary font-semibold mb-2">General Info</h4>
               <ul className="space-y-2 text-sm">
                 {attr.country && <li className="flex justify-between"><span className="text-text-secondary">Country:</span> <span className="text-text-primary">{attr.country}</span></li>}
                 {attr.as_owner && <li className="flex justify-between"><span className="text-text-secondary">AS Owner:</span> <span className="text-text-primary truncate max-w-[200px]" title={attr.as_owner}>{attr.as_owner}</span></li>}
                 {attr.registrar && <li className="flex justify-between"><span className="text-text-secondary">Registrar:</span> <span className="text-text-primary">{attr.registrar}</span></li>}
                 <li className="flex justify-between"><span className="text-text-secondary">Reputation:</span> <span className={reputation < 0 ? 'text-status-error' : 'text-status-success'}>{reputationText}</span></li>
               </ul>
             </div>
             
             {attr.jarm && (
                <div className="bg-bg-tertiary p-4 rounded-lg">
                  <h4 className="text-accent-secondary font-semibold mb-2">JARM Fingerprint</h4>
                  <div className="text-xs font-mono break-all text-text-muted bg-bg-secondary p-2 rounded border border-bg-primary">
                    {attr.jarm}
                  </div>
                </div>
             )}
           </div>
           
           {crowdsourcedContext.length > 0 && (
            <div className="bg-bg-tertiary p-4 rounded-lg border border-status-error/20">
              <h4 className="font-semibold text-status-error mb-2">⚠️ Threat Intelligence Alerts</h4>
              <div className="space-y-2">
                {crowdsourcedContext.slice(0, 3).map((context, index) => (
                  <div key={index} className="bg-bg-secondary border border-status-error/10 p-3 rounded">
                    <div className="font-medium text-status-error text-sm">{context.title}</div>
                    <div className="text-text-secondary text-xs mt-1">{context.details}</div>
                    <div className="text-text-muted text-[10px] mt-1 uppercase tracking-wider">
                      Severity: {context.severity} | Source: {context.source}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }
  };

  const renderWhoisTab = (data) => {
    if (iocType === "domain" || iocType === "url") {
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Registration Info</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between"><span className="text-text-secondary">Registrar:</span> <span className="text-text-primary">{data.registrar || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Created:</span> <span className="text-text-primary">{data.creation_date ? new Date(data.creation_date).toLocaleDateString() : 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Expires:</span> <span className="text-text-primary">{data.expiration_date ? new Date(data.expiration_date).toLocaleDateString() : 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Org:</span> <span className="text-text-primary">{data.org || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Country:</span> <span className="text-text-primary">{data.country || 'N/A'}</span></li>
              </ul>
            </div>
            
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Technical Info</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex flex-col gap-1">
                  <span className="text-text-secondary">Name Servers:</span> 
                  <span className="text-text-primary text-xs font-mono">
                    {Array.isArray(data.name_servers) ? data.name_servers.join(', ') : (data.name_servers || 'N/A')}
                  </span>
                </li>
                <li className="flex flex-col gap-1 mt-2">
                  <span className="text-text-secondary">Status:</span> 
                  <span className="text-text-primary text-xs">
                     {Array.isArray(data.status) ? data.status.slice(0, 3).join(', ') + (data.status.length > 3 ? '...' : '') : (data.status || 'N/A')}
                  </span>
                </li>
                <li className="flex justify-between mt-2"><span className="text-text-secondary">DNSSEC:</span> <span className="text-text-primary">{Array.isArray(data.dnssec) ? data.dnssec.join(', ') : (data.dnssec || 'N/A')}</span></li>
              </ul>
            </div>
          </div>
          
          {data.emails && (
            <div className="bg-bg-tertiary p-4 rounded-lg">
              <h4 className="text-accent-secondary font-semibold mb-2">Contact Emails</h4>
              <div className="flex flex-wrap gap-2">
                {Array.isArray(data.emails) ? data.emails.map(email => (
                  <a key={email} href={`mailto:${email}`} className="text-accent-primary hover:underline text-sm">{email}</a>
                )) : <span className="text-text-primary text-sm">{data.emails}</span>}
              </div>
            </div>
          )}
        </div>
      );
    } else {
      // IP-specific WHOIS display
      return (
        <div className="bg-bg-tertiary p-4 rounded-lg">
          <h4 className="text-accent-secondary font-semibold mb-2">Network Whois</h4>
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between"><span className="text-text-secondary">ASN:</span> <span className="text-text-primary">{data.asn || 'N/A'}</span></li>
            <li className="flex justify-between"><span className="text-text-secondary">Description:</span> <span className="text-text-primary">{data.asn_description || 'N/A'}</span></li>
            <li className="flex justify-between"><span className="text-text-secondary">Country:</span> <span className="text-text-primary">{data.asn_country_code || 'N/A'}</span></li>
            <li className="flex justify-between"><span className="text-text-secondary">CIDR:</span> <span className="text-text-primary">{data.asn_cidr || 'N/A'}</span></li>
            {data.nets && data.nets[0] && (
              <>
                <li className="border-t border-bg-primary my-2 pt-2"></li>
                <li className="flex justify-between"><span className="text-text-secondary">Net Name:</span> <span className="text-text-primary">{data.nets[0].name || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Net Handle:</span> <span className="text-text-primary">{data.nets[0].handle || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Range:</span> <span className="text-text-primary">{data.nets[0].range || 'N/A'}</span></li>
                <li className="flex justify-between"><span className="text-text-secondary">Address:</span> <span className="text-text-primary">{data.nets[0].address || 'N/A'}</span></li>
              </>
            )}
          </ul>
        </div>
      );
    }
  };

  // Render navigation links for tool tabs
  const renderNavigationLinks = () => {
    const otherTabs = availableTabs.filter(tab => tab !== activeTab && tab !== 'overview');
    if (otherTabs.length === 0) return null;

    return (
      <div className="mt-6 pt-4 border-t border-gray-300">
        <h4 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2">View Other Results:</h4>
        <div className="flex flex-wrap gap-2">
          <button 
            onClick={() => setActiveTab('overview')} 
            className="px-3 py-1 text-sm bg-custom-light-blue dark:bg-custom-blue text-accent-primary dark:text-accent-secondary hover:bg-custom-blue dark:hover:bg-custom-light-blue hover:text-custom-cream dark:hover:text-gray-900 transition-colors"
          >
            Overview
          </button>
          {otherTabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-3 py-1 text-sm bg-white dark:bg-bg-secondary text-accent-primary dark:text-accent-secondary hover:bg-custom-light-blue dark:hover:bg-custom-blue hover:text-custom-dark-blue dark:hover:text-custom-cream transition-colors"
            >
              {tab.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
    );
  };

  const availableTabs = getAvailableTabs();

  return (
    <div>
      {/* Tab buttons */}
      <div className="border-b-4 border-gray-200 dark:border-bg-tertiary mb-4">
        <nav className="flex gap-4">
          {availableTabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`pb-2 px-3 py-1 border border-gray-200 dark:border-bg-tertiary shadow-sm text-accent-primary dark:text-accent-secondary hover:text-custom-dark-blue dark:hover:text-custom-cream transition-colors ${
                activeTab === tab ? "bg-accent-primary text-white text-black" : "bg-white dark:bg-bg-secondary"
              }`}
            >
              {tab.toUpperCase()}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div className="p-4 border border-gray-200 dark:border-bg-tertiary shadow-sm bg-white dark:bg-bg-secondary">
        {activeTab === "overview"
          ? renderOverview()
          : renderToolTab(activeTab, results[activeTab])}
      </div>
    </div>
  );
}
