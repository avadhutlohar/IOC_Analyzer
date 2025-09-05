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
            <a href={toolLinks.abuseipdb} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.abuseipdb?.error && (
          <li className="text-custom-blue dark:text-custom-light-blue">AbuseIPDB: {typeof results.abuseipdb.error === 'object' ? (results.abuseipdb.error.message || JSON.stringify(results.abuseipdb.error)) : results.abuseipdb.error}</li>
        )}
        
        {results.otx && !results.otx.error && results.otx.pulse_info && (
          <li>OTX Pulses: {results.otx.pulse_info.count || 'N/A'} 
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.otx?.error && (
          <li className="text-red-600 dark:text-red-400">OTX: {typeof results.otx.error === 'object' ? (results.otx.error.message || JSON.stringify(results.otx.error)) : results.otx.error}</li>
        )}
        
        {results.shodan && !results.shodan.error && results.shodan.asn && (
          <li>Shodan ASN: {results.shodan.asn} 
            <a href={toolLinks.shodan} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
        
        {results.whois && !results.whois.error && (
          <li>
            WHOIS ASN: {results.whois.asn || "N/A"} | Country:{" "}
            {results.whois.asn_country_code || "N/A"}
            <a href={toolLinks.whois} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
        
        {results.whois && !results.whois.error && (
          <li>
            WHOIS Org: {results.whois.org || "N/A"} | Country: {results.whois.country || "N/A"}
            <a href={toolLinks.whois} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
          </li>
        )}
        {results.virustotal?.error && (
          <li className="text-red-600">VirusTotal: {typeof results.virustotal.error === 'object' ? (results.virustotal.error.message || JSON.stringify(results.virustotal.error)) : results.virustotal.error}</li>
        )}
        
        {results.whois && !results.whois.error && (
          <li>
            WHOIS Org: {results.whois.org || "N/A"} | Country: {results.whois.country || "N/A"}
            <a href={toolLinks.whois} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.otx} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
            <a href={toolLinks.virustotal} target="_blank" rel="noopener noreferrer" className="ml-2 text-custom-blue dark:text-custom-light-blue hover:underline text-sm">[View Details]</a>
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
    <ul className="list-disc ml-6 space-y-1">
      <li>Score: {data.data?.abuseConfidenceScore || 'N/A'}%</li>
      <li>ISP: {data.data?.isp || 'N/A'}</li>
      <li>Usage Type: {data.data?.usageType || 'N/A'}</li>
      <li>Domain: {data.data?.domain || 'N/A'}</li>
      <li>Total Reports: {data.data?.totalReports || 'N/A'}</li>
    </ul>
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
                  <div key={index} className="bg-custom-light-gray dark:bg-custom-dark-gray border p-3">
                    <div className="font-medium">
                      <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-custom-blue dark:text-custom-light-blue hover:underline">
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
            {data.whois && <li>WHOIS: <a href={data.whois} target="_blank" rel="noopener noreferrer" className="text-custom-blue dark:text-custom-light-blue hover:underline">Available</a></li>}
            {data.alexa && <li>Alexa Info: <a href={data.alexa} target="_blank" rel="noopener noreferrer" className="text-custom-blue dark:text-custom-light-blue hover:underline">Available</a></li>}
            <li>Pulse Count: <span className={pulseCount > 0 ? 'text-red-600 font-semibold' : 'text-green-600'}>{pulseCount}</span></li>
          </ul>
          
          {data.pulse_info?.pulses && data.pulse_info.pulses.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Pulses:</h4>
              <div className="space-y-2">
                {data.pulse_info.pulses.slice(0, 5).map((pulse, index) => (
                  <div key={index} className="bg-gray-50 border p-3">
                    <div className="font-medium">
                      <a href={`https://otx.alienvault.com/pulse/${pulse.id}`} target="_blank" rel="noopener noreferrer" className="text-custom-blue dark:text-custom-light-blue hover:underline">
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
    <ul className="list-disc ml-6 space-y-1">
      <li>ASN: {data.asn || 'N/A'}</li>
      <li>ISP: {data.isp || 'N/A'}</li>
      <li>Country: {data.country_name || 'N/A'}</li>
      <li>Open Ports: {data.ports?.join(", ") || 'N/A'}</li>
    </ul>
  );

  const renderVirusTotalTab = (data) => {
    const attr = data.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const reputation = attr.reputation || 0;
    const reputationText = reputation > 0 ? `${reputation} (Good)` : reputation < 0 ? `${reputation} (Bad)` : `${reputation} (Neutral)`;
    const crowdsourcedContext = attr.crowdsourced_context || [];
    
    if (iocType === "hash") {
      const malicious = stats.malicious || 0;
      const total = Object.values(stats).reduce((sum, count) => sum + (count || 0), 0);
      const lastAnalysisDate = attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleString() : 'N/A';
      
      return (
        <div className="space-y-3">
          <ul className="list-disc ml-6 space-y-1">
            <li>Reputation: <span className={reputation > 0 ? 'text-green-600' : reputation < 0 ? 'text-red-600' : 'text-gray-600'}>{reputationText}</span></li>
            <li>Detection Results:</li>
            <ul className="list-disc ml-6 space-y-1">
              <li className="text-green-600">Harmless: {stats.harmless || 0}</li>
              <li className="text-red-600">Malicious: {stats.malicious || 0}</li>
              <li className="text-yellow-600">Suspicious: {stats.suspicious || 0}</li>
              <li className="text-gray-600">Undetected: {stats.undetected || 0}</li>
              <li className="text-gray-500">Timeout: {stats.timeout || 0}</li>
            </ul>
            <li>Score: <span className="font-semibold">{malicious}/{total}</span></li>
            <li>File Name: {(() => {
              // Check if meaningful_name is actually meaningful
              if (attr.meaningful_name && 
                  !attr.meaningful_name.includes('phpa9a9cak2oaiv4f40YPq') &&
                  !attr.meaningful_name.match(/^[a-zA-Z0-9]{15,}$/) &&
                  attr.meaningful_name.length > 3) {
                return attr.meaningful_name;
              }
              
              if (attr.names && attr.names.length > 0) {
                // Find the most meaningful filename
                const meaningfulNames = attr.names.filter(name => 
                  !name.match(/^[a-f0-9]{32,}/) && // Not just a hash
                  !name.match(/\.(com|exe|bin|txt)-\d+$/) && // Not filename with random number suffix
                  !name.includes('phpa9a9cak2oaiv4f40YPq') && // Not temp/random names
                  name.length > 3 && // Not too short
                  name.length < 50 && // Not too long
                  !name.match(/^[a-zA-Z0-9]{15,}$/) // Not random alphanumeric strings
                );
                
                if (meaningfulNames.length > 0) {
                  // Prefer simple, recognizable names without random suffixes
                  const simpleNames = meaningfulNames.filter(name => 
                    (name === 'eicar.com' || name === 'eicar.txt' || name === 'eicar.exe' ||
                     name === 'eicar.csv' || name === 'eicar.com.txt' ||
                     (name.toLowerCase().includes('eicar') && !name.match(/-\d+$/)) ||
                     (name.toLowerCase().includes('test') && !name.match(/-\d+$/)))
                  );
                  
                  if (simpleNames.length > 0) {
                    // Prefer the simplest name
                    const preferred = simpleNames.find(name => name === 'eicar.com') ||
                                    simpleNames.find(name => name === 'eicar.txt') ||
                                    simpleNames.find(name => name === 'eicar.exe') ||
                                    simpleNames[0];
                    return preferred;
                  }
                  
                  // If no simple names, return the first meaningful name
                  return meaningfulNames[0];
                }
                
                // Fallback to first name if no meaningful names found
                return attr.names[0];
              }
              return 'N/A';
            })()}</li>
            <li>Size: {attr.size ? `${(attr.size / 1024).toFixed(2)} KB` : 'N/A'}</li>
            <li>Last Analysis Date: {lastAnalysisDate}</li>
            {attr.categories && attr.categories.length > 0 && (
              <li>Categories: {attr.categories.join(", ")}</li>
            )}
          </ul>
        </div>
      );
    } else if (iocType === "url") {
      // URL-specific VirusTotal display
      const score = `${stats.malicious || 0}/${(stats.malicious || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0)}`;
      const creationDate = attr.creation_date ? new Date(attr.creation_date * 1000).toLocaleDateString() : 'N/A';
      const lastAnalysisDate = attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleDateString() : 'N/A';
      
      return (
        <div className="space-y-3">
          <ul className="list-disc ml-6 space-y-1">
            <li>Reputation: <span className={reputation > 0 ? 'text-green-600' : reputation < 0 ? 'text-red-600' : 'text-gray-600'}>{reputationText}</span></li>
            <li>Detection Results:</li>
            <ul className="list-disc ml-6 space-y-1">
              <li className="text-green-600">Harmless: {stats.harmless || 0}</li>
              <li className="text-red-600">Malicious: {stats.malicious || 0}</li>
              <li className="text-yellow-600">Suspicious: {stats.suspicious || 0}</li>
              <li className="text-gray-600">Undetected: {stats.undetected || 0}</li>
            </ul>
            <li>Score: <span className={stats.malicious > 0 ? 'text-red-600 font-semibold' : 'text-green-600'}>{score}</span></li>
            <li>Creation Date: {creationDate}</li>
            <li>Last Analysis Date: {lastAnalysisDate}</li>
            {attr.registrar && <li>Domain registrar url: {attr.registrar}</li>}
            <li>Domain name: {data.data?.id || ioc}</li>
            {attr.last_dns_records && attr.last_dns_records.length > 0 && (
              <li>IP Address: {attr.last_dns_records[0].value || 'N/A'}</li>
            )}
            {attr.country && <li>Administrative country: {attr.country}</li>}
            {attr.categories && attr.categories.length > 0 && (
              <li>Categories: {attr.categories.join(", ")}</li>
            )}
          </ul>
          
          {crowdsourcedContext.length > 0 && (
            <div className="mt-4">
              <h4 className="font-semibold text-red-600 mb-2">⚠️ Threat Intelligence Alerts:</h4>
              <div className="space-y-2">
                {crowdsourcedContext.slice(0, 3).map((context, index) => (
                  <div key={index} className="bg-red-50 border border-red-200 p-3">
                    <div className="font-medium text-red-800">{context.title}</div>
                    <div className="text-red-700 text-sm">{context.details}</div>
                    <div className="text-red-600 text-xs mt-1">
                      Severity: {context.severity} | Source: {context.source}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    } else if (iocType === "domain") {
      // Domain-specific VirusTotal display
      const score = `${stats.malicious || 0}/${(stats.malicious || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0)}`;
      const creationDate = attr.creation_date ? new Date(attr.creation_date * 1000).toLocaleDateString() : 'N/A';
      const lastAnalysisDate = attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleDateString() : 'N/A';
      
      return (
        <div className="space-y-3">
          <ul className="list-disc ml-6 space-y-1">
            <li>Reputation: <span className={reputation > 0 ? 'text-green-600' : reputation < 0 ? 'text-red-600' : 'text-gray-600'}>{reputationText}</span></li>
            <li>Detection Results:</li>
            <ul className="list-disc ml-6 space-y-1">
              <li className="text-green-600">Harmless: {stats.harmless || 0}</li>
              <li className="text-red-600">Malicious: {stats.malicious || 0}</li>
              <li className="text-yellow-600">Suspicious: {stats.suspicious || 0}</li>
              <li className="text-gray-600">Undetected: {stats.undetected || 0}</li>
              <li className="text-gray-500">Timeout: {stats.timeout || 0}</li>
            </ul>
            <li>Score: <span className={stats.malicious > 0 ? 'text-red-600 font-semibold' : 'text-green-600'}>{score}</span></li>
            <li>Creation Date: {creationDate}</li>
            <li>Last Analysis Date: {lastAnalysisDate}</li>
            {attr.registrar && <li>Domain registrar url: {attr.registrar}</li>}
            <li>Domain name: {data.data?.id || ioc}</li>
            {attr.last_dns_records && attr.last_dns_records.length > 0 && (
              <li>IP Address: {attr.last_dns_records[0].value || 'N/A'}</li>
            )}
            {attr.country && <li>Administrative country: {attr.country}</li>}
            {attr.categories && attr.categories.length > 0 && (
              <li>Categories: {attr.categories.join(", ")}</li>
            )}
          </ul>
          
          {crowdsourcedContext.length > 0 && (
            <div className="mt-4">
              <h4 className="font-semibold text-red-600 mb-2">⚠️ Threat Intelligence Alerts:</h4>
              <div className="space-y-2">
                {crowdsourcedContext.slice(0, 3).map((context, index) => (
                  <div key={index} className="bg-red-50 border border-red-200 p-3">
                    <div className="font-medium text-red-800">{context.title}</div>
                    <div className="text-red-700 text-sm">{context.details}</div>
                    <div className="text-red-600 text-xs mt-1">
                      Severity: {context.severity} | Source: {context.source}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    } else {
      // IP-specific VirusTotal display
      return (
        <div className="space-y-3">
          <ul className="list-disc ml-6 space-y-1">
             <li>Reputation Score: <span className={reputation > 0 ? 'text-green-600' : reputation < 0 ? 'text-red-600' : 'text-gray-600'}>{reputationText}</span></li>
             <li>Detection Results: <span className="font-semibold">{stats.malicious || 0}/{(stats.malicious || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0)}</span> engines flagged as malicious</li>
             <li>Detailed Analysis:</li>
             <ul className="list-disc ml-6 space-y-1">
               <li className="text-green-600">Harmless: {stats.harmless || 0}</li>
               <li className="text-red-600">Malicious: {stats.malicious || 0}</li>
               <li className="text-yellow-600">Suspicious: {stats.suspicious || 0}</li>
               <li className="text-gray-600">Undetected: {stats.undetected || 0}</li>
               <li className="text-gray-500">Timeout: {stats.timeout || 0}</li>
             </ul>
             {attr.as_owner && <li>AS Owner: {attr.as_owner}</li>}
             {attr.country && <li>Country: {attr.country}</li>}
           </ul>
          
          {crowdsourcedContext.length > 0 && (
            <div className="mt-4">
              <h4 className="font-semibold text-red-600 mb-2">⚠️ Threat Intelligence Alerts:</h4>
              <div className="space-y-2">
                {crowdsourcedContext.slice(0, 3).map((context, index) => (
                  <div key={index} className="bg-red-50 border border-red-200 p-3">
                    <div className="font-medium text-red-800">{context.title}</div>
                    <div className="text-red-700 text-sm">{context.details}</div>
                    <div className="text-red-600 text-xs mt-1">
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
        <ul className="list-disc ml-6 space-y-1">
          <li>Registrar: {data.registrar || 'N/A'}</li>
          <li>Creation Date: {data.creation_date || 'N/A'}</li>
          <li>Expiry Date: {data.expiration_date || 'N/A'}</li>
          <li>Org: {data.org || 'N/A'}</li>
          <li>Country: {data.country || 'N/A'}</li>
        </ul>
      );
    } else {
      // IP-specific WHOIS display
      return (
        <ul className="list-disc ml-6 space-y-1">
          <li>ASN: {data.asn || 'N/A'}</li>
          <li>ASN Description: {data.asn_description || 'N/A'}</li>
          <li>Country: {data.asn_country_code || 'N/A'}</li>
          <li>CIDR: {data.asn_cidr || 'N/A'}</li>
          {data.nets && data.nets[0] && (
            <>
              <li>Network Name: {data.nets[0].name || 'N/A'}</li>
              <li>Description: {data.nets[0].description || 'N/A'}</li>
              <li>Address: {data.nets[0].address || 'N/A'}</li>
            </>
          )}
        </ul>
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
            className="px-3 py-1 text-sm bg-custom-light-blue dark:bg-custom-blue text-custom-blue dark:text-custom-light-blue hover:bg-custom-blue dark:hover:bg-custom-light-blue hover:text-custom-cream dark:hover:text-custom-dark-gray transition-colors"
          >
            Overview
          </button>
          {otherTabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-3 py-1 text-sm bg-custom-light-bg dark:bg-custom-dark-gray text-custom-blue dark:text-custom-light-blue hover:bg-custom-light-blue dark:hover:bg-custom-blue hover:text-custom-dark-blue dark:hover:text-custom-cream transition-colors"
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
      <div className="border-b-4 border-retro-dark-border mb-4">
        <nav className="flex gap-4">
          {availableTabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`pb-2 px-3 py-1 border-3 border-retro-dark-border shadow-retro text-custom-blue dark:text-custom-light-blue hover:text-custom-dark-blue dark:hover:text-custom-cream transition-colors ${
                activeTab === tab ? "bg-retro-terminal-amber text-black" : "bg-custom-light-bg dark:bg-custom-dark-gray"
              }`}
            >
              {tab.toUpperCase()}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div className="p-4 border-4 border-retro-dark-border shadow-retro bg-custom-light-bg dark:bg-custom-dark-gray">
        {activeTab === "overview"
          ? renderOverview()
          : renderToolTab(activeTab, results[activeTab])}
      </div>
    </div>
  );
}
