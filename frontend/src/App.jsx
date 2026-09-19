import React, { useState } from 'react';
import Header from './components/Header';
import StatCard from './components/StatCard';
import ModuleGrid from './components/ModuleGrid';
import TerminalConsole from './components/TerminalConsole';
import FindingsTable from './components/FindingsTable';
import ConfigModal from './components/ConfigModal';
import JsonViewerModal from './components/JsonViewerModal';
import HtmlReportModal from './components/HtmlReportModal';
import { initialModules, initialConfig, sampleFindings } from './data/initialData';

export default function App() {
  const [modules, setModules] = useState(initialModules);
  const [config, setConfig] = useState(initialConfig);
  const [findings, setFindings] = useState(sampleFindings);
  const [logs, setLogs] = useState([
    { time: new Date().toLocaleTimeString(), text: 'SENTINEL-12 SITUATION ROOM INTEL SYSTEM INITIALIZED.', type: 'info' },
    { time: new Date().toLocaleTimeString(), text: `TARGET COORD SET TO ${initialConfig.base_url}`, type: 'info' }
  ]);
  const [isScanning, setIsScanning] = useState(false);
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [isJsonModalOpen, setIsJsonModalOpen] = useState(false);
  const [isHtmlModalOpen, setIsHtmlModalOpen] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const criticalCount = findings.filter(f => f.severity === 'critical').length;

  // Toggle Module Selection
  const handleToggleModule = (id) => {
    setModules(prev => prev.map(m => m.id === id ? { ...m, selected: !m.selected } : m));
  };

  // Toggle Select All / Deselect All
  const handleToggleAll = () => {
    const allSelected = modules.every(m => m.selected);
    setModules(prev => prev.map(m => ({ ...m, selected: !allSelected })));
  };

  // Start Full Suite Scan
  const handleStartScan = () => {
    const selectedMods = modules.filter(m => m.selected);
    if (selectedMods.length === 0) {
      alert('Please select at least one security sector vector to execute.');
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setLogs(prev => [
      ...prev,
      { time: new Date().toLocaleTimeString(), text: '==================================================', type: 'info' },
      { time: new Date().toLocaleTimeString(), text: `ENGAGING FULL BATTLE-STATION SUITE AGAINST ${config.base_url}`, type: 'info' },
      { time: new Date().toLocaleTimeString(), text: `PROBING ${selectedMods.length} TACTICAL SECTOR THREAT VECTORS...`, type: 'info' },
      { time: new Date().toLocaleTimeString(), text: '==================================================', type: 'info' }
    ]);

    // Scan sequence
    let currentStep = 0;
    const totalSteps = selectedMods.length;

    const interval = setInterval(() => {
      if (currentStep >= totalSteps) {
        clearInterval(interval);
        setIsScanning(false);
        setScanProgress(100);
        setLogs(prev => [
          ...prev,
          { time: new Date().toLocaleTimeString(), text: '==================================================', type: 'passed' },
          { time: new Date().toLocaleTimeString(), text: 'SITUATION ROOM PROBE COMPLETE. TELEMETRY AGGREGATED.', type: 'passed' },
          { time: new Date().toLocaleTimeString(), text: '==================================================', type: 'passed' }
        ]);
        return;
      }

      const currentMod = selectedMods[currentStep];
      const timeStr = new Date().toLocaleTimeString();

      setLogs(prev => [
        ...prev,
        { time: timeStr, text: `PROBING SECTOR [${currentMod.code.toUpperCase()}]: ${currentMod.name}...`, type: 'info' },
        { time: timeStr, text: `[TELEMETRY] Executing attack vector probes for ${currentMod.name}...`, type: 'info' }
      ]);

      // Add a simulated finding occasionally
      if (currentStep % 2 === 0) {
        const newFinding = {
          id: `f-${Date.now()}-${currentStep}`,
          severity: currentStep === 0 ? 'critical' : (currentStep === 2 ? 'high' : 'medium'),
          module: currentMod.code,
          moduleName: currentMod.name,
          message: `EXPLOIT VULNERABILITY DETECTED IN SECTOR ${currentMod.name}: State / Authorization bypass flaw`,
          details: {
            endpoint: `/api/v1/${currentMod.code}/test-probe`,
            method: 'PATCH',
            status_code: 200,
            cwe: currentMod.owasp,
            recommendation: `Enforce strict server-side authorization boundaries on sector ${currentMod.name}.`
          },
          timestamp: new Date().toLocaleString()
        };

        setFindings(prev => [newFinding, ...prev]);

        setLogs(prev => [
          ...prev,
          { time: timeStr, text: `[EXPLOIT DETECTED] [${newFinding.severity.toUpperCase()}] ${newFinding.message}`, type: newFinding.severity }
        ]);
      } else {
        setLogs(prev => [
          ...prev,
          { time: timeStr, text: `[DEFENSE VERIFIED] Sector [${currentMod.code.toUpperCase()}] passed baseline checks.`, type: 'passed' }
        ]);
      }

      currentStep++;
      setScanProgress(Math.round((currentStep / totalSteps) * 100));
    }, 1200);
  };

  // Run Single Module
  const handleRunModule = (id) => {
    const mod = modules.find(m => m.id === id);
    if (!mod) return;

    setIsScanning(true);
    const timeStr = new Date().toLocaleTimeString();

    setLogs(prev => [
      ...prev,
      { time: timeStr, text: `[SECTOR PROBE] Deploying targeted probe for: ${mod.name}...`, type: 'info' },
      { time: timeStr, text: `Probing target ${config.base_url} for ${mod.code} vulnerabilities...`, type: 'info' }
    ]);

    setTimeout(() => {
      setIsScanning(false);
      setLogs(prev => [
        ...prev,
        { time: new Date().toLocaleTimeString(), text: `[DEFENSE VERIFIED] Sector ${mod.name} checks completed.`, type: 'passed' }
      ]);
    }, 1500);
  };

  const handleStopScan = () => {
    setIsScanning(false);
    setLogs(prev => [
      ...prev,
      { time: new Date().toLocaleTimeString(), text: 'OPERATIONS ABORTED BY USER.', type: 'critical' }
    ]);
  };

  // Generate Report Objects
  const jsonReportData = {
    metadata: {
      target: config.base_url,
      generated_at: new Date().toISOString(),
      total_findings: findings.length,
      defcon_level: criticalCount > 0 ? 1 : 5
    },
    findings: findings,
    configuration: config
  };

  const generateHtmlReportContent = () => {
    return `<!DOCTYPE html>
<html>
<head>
  <title>SENTINEL-12 DEFCON 1 SITUATION ROOM REPORT</title>
  <style>
    body { font-family: 'JetBrains Mono', monospace; background: #0a0a0a; color: #f5f5f5; padding: 40px; margin: 0; line-height: 1.6; }
    h1 { color: #dc2626; font-size: 24px; border-bottom: 2px solid #333; padding-bottom: 12px; }
    .header-card { background: #141414; padding: 20px; border-radius: 4px; margin-bottom: 24px; border: 1px solid #333; }
    .card { background: #171717; padding: 20px; border-radius: 4px; margin-bottom: 16px; border: 1px solid #262626; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 2px; font-weight: bold; font-size: 12px; text-transform: uppercase; }
    .critical { background: #2b1212; color: #f87171; border: 1px solid #991b1b; }
    .high { background: #2b170c; color: #fb923c; border: 1px solid #9a3412; }
    .medium { background: #2a200a; color: #facc15; border: 1px solid #92400e; }
    .low { background: #262626; color: #e4e4e7; border: 1px solid #52525b; }
    .passed { background: #0d2818; color: #4ade80; border: 1px solid #15803d; }
    pre { background: #050505; padding: 12px; border-radius: 4px; border: 1px solid #262626; color: #d4d4d4; overflow-x: auto; font-size: 12px; }
  </style>
</head>
<body>
  <h1>SENTINEL-12 // SITUATION ROOM INTEL REPORT</h1>
  <div class="header-card">
    <p><strong>TARGET COORD:</strong> ${config.base_url}</p>
    <p><strong>GENERATED:</strong> ${new Date().toLocaleString()}</p>
    <p><strong>DEFCON STATUS:</strong> ${criticalCount > 0 ? 'DEFCON 1: COCKED PISTOL' : 'DEFCON 5: NORMAL'}</p>
    <p><strong>TOTAL AUDIT FINDINGS:</strong> ${findings.length}</p>
  </div>
  <h2>CLASSIFIED VULNERABILITY LOGS (${findings.length})</h2>
  ${findings.map(f => `
    <div class="card">
      <span class="badge ${f.severity}">[${f.severity.toUpperCase()}]</span>
      <h3 style="margin: 8px 0; color: #fff;">${f.message}</h3>
      <p style="color: #a3a3a3; font-size: 13px;">SECTOR MODULE: ${f.moduleName || f.module} | ${f.timestamp}</p>
      ${f.details ? `<pre>${JSON.stringify(f.details, null, 2)}</pre>` : ''}
    </div>
  `).join('')}
</body>
</html>`;
  };

  return (
    <div className="app-container">
      
      {/* Top Header Navigation */}
      <Header 
        config={config}
        isScanning={isScanning}
        onStartScan={handleStartScan}
        onStopScan={handleStopScan}
        onOpenConfig={() => setIsConfigOpen(true)}
        onExportJson={() => setIsJsonModalOpen(true)}
        onExportHtml={() => setIsHtmlModalOpen(true)}
        criticalCount={criticalCount}
      />

      {/* Main Dashboard Layout */}
      <main className="main-content">
        
        {/* Progress bar during scan */}
        {isScanning && (
          <div style={{ width: '100%', backgroundColor: '#141414', borderRadius: '0.125rem', height: '4px', overflow: 'hidden' }}>
            <div style={{ width: `${scanProgress}%`, height: '100%', background: criticalCount > 0 ? '#dc2626' : '#16a34a' }}></div>
          </div>
        )}

        {/* DEFCON Threat Gauge & Executive Summary */}
        <StatCard 
          findings={findings}
          modules={modules}
        />

        {/* 12 Sector Threat Vectors Grid */}
        <ModuleGrid 
          modules={modules}
          onToggleModule={handleToggleModule}
          onToggleAll={handleToggleAll}
          onRunModule={handleRunModule}
          isScanning={isScanning}
        />

        {/* Console Operations Log Terminal */}
        <TerminalConsole 
          logs={logs}
          onClearLogs={() => setLogs([])}
        />

        {/* Situation Room Intel & Findings Table */}
        <FindingsTable 
          findings={findings}
        />

      </main>

      {/* Settings Modal */}
      {isConfigOpen && (
        <ConfigModal 
          config={config}
          onSave={(newCfg) => setConfig(newCfg)}
          onClose={() => setIsConfigOpen(false)}
        />
      )}

      {/* Direct JSON Viewer Modal */}
      {isJsonModalOpen && (
        <JsonViewerModal 
          reportData={jsonReportData}
          onClose={() => setIsJsonModalOpen(false)}
        />
      )}

      {/* Direct HTML Report Modal / Preview */}
      {isHtmlModalOpen && (
        <HtmlReportModal 
          htmlContent={generateHtmlReportContent()}
          onClose={() => setIsHtmlModalOpen(false)}
        />
      )}

    </div>
  );
}
