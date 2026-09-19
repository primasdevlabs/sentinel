import React from 'react';
import { 
  ShieldExclamationIcon, 
  ExclamationTriangleIcon, 
  CheckCircleIcon, 
  CpuChipIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';

export default function StatCard({ findings, modules }) {
  // Calculate counts
  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    passed: findings.filter(f => f.severity === 'passed').length,
    info: findings.filter(f => f.severity === 'info').length
  };

  // Compute Risk Score: (CRITICAL x 10) + (HIGH x 5) + (MEDIUM x 2) + (LOW x 1)
  const riskScore = (counts.critical * 10) + (counts.high * 5) + (counts.medium * 2) + (counts.low * 1);

  // DEFCON Threat Status Calculation
  let defconLevel = 5;
  let defconLabel = 'DEFCON 5 // FADE OUT';
  let defconColor = '#16a34a';
  let defconBg = '#0d2818';

  if (counts.critical >= 1) {
    defconLevel = 1;
    defconLabel = 'DEFCON 1 // COCKED PISTOL';
    defconColor = '#dc2626';
    defconBg = '#2b1212';
  } else if (counts.high >= 1) {
    defconLevel = 2;
    defconLabel = 'DEFCON 2 // FAST PACE';
    defconColor = '#ea580c';
    defconBg = '#2b170c';
  } else if (counts.medium >= 1) {
    defconLevel = 3;
    defconLabel = 'DEFCON 3 // ROUND HOUSE';
    defconColor = '#d97706';
    defconBg = '#2a200a';
  } else if (counts.low >= 1) {
    defconLevel = 4;
    defconLabel = 'DEFCON 4 // DOUBLE TAKE';
    defconColor = '#71717a';
    defconBg = '#262626';
  }

  const activeModulesCount = modules.filter(m => m.selected).length;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
      
      {/* DEFCON Status Meter Card */}
      <div className="glass-panel glass-panel-hover" style={{ padding: '1.25rem', background: defconBg, borderColor: defconColor }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
            SITUATION ROOM THREAT LEVEL
          </span>
          <ShieldExclamationIcon style={{ width: '20px', height: '20px', color: defconColor }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.75rem', marginTop: '0.5rem' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '2.5rem', fontWeight: 900, color: defconColor, lineHeight: 1 }}>
            DEFCON {defconLevel}
          </span>
        </div>
        <div style={{ marginTop: '0.5rem' }}>
          <span className="badge" style={{ background: defconBg, color: defconColor, borderColor: defconColor }}>
            {defconLabel}
          </span>
        </div>
      </div>

      {/* Risk Score Matrix Card */}
      <div className="glass-panel glass-panel-hover" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
            RISK MATRIX METRIC
          </span>
          <ChartBarIcon style={{ width: '20px', height: '20px', color: '#f5f5f5' }} />
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '2.5rem', fontWeight: 900, color: '#ffffff', marginTop: '0.5rem', lineHeight: 1 }}>
          {riskScore}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
          Weighted threat index calculation
        </p>
      </div>

      {/* Critical Threats */}
      <div className="glass-panel glass-panel-hover" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
            CRITICAL EXPLOITS
          </span>
          <ShieldExclamationIcon style={{ width: '20px', height: '20px', color: '#dc2626' }} />
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '2.5rem', fontWeight: 900, color: counts.critical > 0 ? '#dc2626' : '#ffffff', marginTop: '0.5rem', lineHeight: 1 }}>
          {counts.critical}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
          Immediate battle-station remediation
        </p>
      </div>

      {/* High Vulnerabilities */}
      <div className="glass-panel glass-panel-hover" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
            HIGH VULNERABILITIES
          </span>
          <ExclamationTriangleIcon style={{ width: '20px', height: '20px', color: '#ea580c' }} />
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '2.5rem', fontWeight: 900, color: counts.high > 0 ? '#ea580c' : '#ffffff', marginTop: '0.5rem', lineHeight: 1 }}>
          {counts.high}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
          Elevated risk mitigation required
        </p>
      </div>

      {/* Passed Controls */}
      <div className="glass-panel glass-panel-hover" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
            VERIFIED DEFENSES
          </span>
          <CheckCircleIcon style={{ width: '20px', height: '20px', color: '#16a34a' }} />
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '2.5rem', fontWeight: 900, color: '#16a34a', marginTop: '0.5rem', lineHeight: 1 }}>
          {counts.passed}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
          Hardened operational controls
        </p>
      </div>

    </div>
  );
}
