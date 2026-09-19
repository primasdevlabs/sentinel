import React from 'react';
import { 
  ShieldCheckIcon, 
  PlayIcon, 
  StopIcon, 
  Cog6ToothIcon, 
  ArrowDownTrayIcon,
  GlobeAltIcon
} from '@heroicons/react/24/solid';

export default function Header({ 
  config, 
  isScanning, 
  onStartScan, 
  onStopScan, 
  onOpenConfig, 
  onExportJson, 
  onExportHtml,
  criticalCount
}) {
  const defconLevel = criticalCount > 0 ? 1 : (isScanning ? 2 : 5);
  const defconText = criticalCount > 0 
    ? 'DEFCON 1: COCKED PISTOL (MAX ALERT)' 
    : (isScanning ? 'DEFCON 2: FAST PACE (SCAN ACTIVE)' : 'DEFCON 5: FADE OUT (NORMAL)');

  return (
    <header className="glass-panel" style={{ borderTop: 'none', borderLeft: 'none', borderRight: 'none', borderRadius: 0, padding: '1rem 1.5rem' }}>
      <div style={{ maxWidth: '1440px', margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        
        {/* Brand & Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ 
            width: '44px', 
            height: '44px', 
            borderRadius: '0.25rem', 
            background: defconLevel === 1 ? '#2b1212' : '#141414',
            border: `1px solid ${defconLevel === 1 ? '#dc2626' : '#333333'}`,
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center'
          }}>
            <ShieldCheckIcon style={{ width: '26px', height: '26px', color: defconLevel === 1 ? '#dc2626' : '#16a34a' }} />
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
              <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.25rem', fontWeight: 800, letterSpacing: '0.05em', color: '#ffffff' }}>
                SENTINEL-12 // SITUATION ROOM
              </h1>
              <span className="badge badge-passed" style={{ fontSize: '0.6875rem' }}>
                OPS v2.0.0
              </span>
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '0.5rem', 
                background: defconLevel === 1 ? '#2b1212' : '#141414', 
                border: `1px solid ${defconLevel === 1 ? '#dc2626' : '#333333'}`, 
                padding: '0.2rem 0.6rem', 
                borderRadius: '0.125rem', 
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)'
              }}>
                <span className="pulse-indicator" style={{ backgroundColor: defconLevel === 1 ? '#dc2626' : (isScanning ? '#ea580c' : '#16a34a') }}></span>
                <span style={{ color: defconLevel === 1 ? '#f87171' : (isScanning ? '#fdba74' : '#86efac'), fontWeight: 700 }}>
                  {defconText}
                </span>
              </div>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.125rem', fontFamily: 'var(--font-mono)' }}>
              TACTICAL THREAT & LOGIC AUDITING SYSTEM
            </p>
          </div>
        </div>

        {/* Target Indicator & Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          
          {/* Target Host Badge */}
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '0.5rem', 
            background: '#141414', 
            border: '1px solid #333333', 
            padding: '0.5rem 0.875rem', 
            borderRadius: '0.25rem',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono)'
          }}>
            <GlobeAltIcon style={{ width: '16px', height: '16px', color: '#a3a3a3' }} />
            <span style={{ color: 'var(--text-muted)' }}>TARGET COORD:</span>
            <span style={{ color: '#f5f5f5', fontWeight: 600 }}>
              {config.base_url}
            </span>
          </div>

          {/* Config Button */}
          <button 
            className="btn btn-secondary" 
            onClick={onOpenConfig}
            title="Configure target URL and session tokens"
          >
            <Cog6ToothIcon style={{ width: '16px', height: '16px' }} />
            <span>CONFIG LAB</span>
          </button>

          {/* Export JSON Button */}
          <button 
            className="btn btn-secondary" 
            onClick={onExportJson}
            title="Export Findings to JSON"
          >
            <ArrowDownTrayIcon style={{ width: '14px', height: '14px' }} />
            <span>JSON INTEL</span>
          </button>

          {/* Export HTML Button */}
          <button 
            className="btn btn-secondary" 
            onClick={onExportHtml}
            title="Export HTML Audit Dashboard"
          >
            <ArrowDownTrayIcon style={{ width: '14px', height: '14px' }} />
            <span>HTML REPORT</span>
          </button>

          {/* Run / Stop Actions */}
          {isScanning ? (
            <button className="btn btn-danger" onClick={onStopScan}>
              <StopIcon style={{ width: '16px', height: '16px' }} />
              <span>ABORT OPS</span>
            </button>
          ) : (
            <button className="btn btn-primary" onClick={onStartScan}>
              <PlayIcon style={{ width: '16px', height: '16px' }} />
              <span>ENGAGE FULL SUITE</span>
            </button>
          )}

        </div>
      </div>
    </header>
  );
}
