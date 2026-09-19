import React, { useState } from 'react';
import { 
  ShieldExclamationIcon, 
  MagnifyingGlassIcon,
  ChevronRightIcon,
  CodeBracketIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';

export default function FindingsTable({ findings }) {
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Filtering
  const filteredFindings = findings.filter(f => {
    const matchesSeverity = filterSeverity === 'all' || f.severity === filterSeverity;
    const matchesSearch = searchQuery === '' || 
      f.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.moduleName && f.moduleName.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSeverity && matchesSearch;
  });

  const getBadgeClass = (severity) => {
    switch (severity) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      case 'info': return 'badge-info';
      case 'passed': return 'badge-passed';
      default: return 'badge-info';
    }
  };

  const severityCounts = {
    all: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    passed: findings.filter(f => f.severity === 'passed').length,
  };

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      
      {/* Header & Filters */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.125rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem', letterSpacing: '0.05em' }}>
            <ShieldExclamationIcon style={{ width: '20px', height: '20px', color: '#dc2626' }} />
            SITUATION ROOM INTEL & TARGET VULNERABILITIES ({findings.length})
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.125rem', fontFamily: 'var(--font-mono)' }}>
            CLASSIFIED LOG OF DETECTED EXPLOITS, LOGIC FLAWS, AND VERIFIED DEFENSES
          </p>
        </div>

        {/* Search Input */}
        <div style={{ position: 'relative', width: '260px' }}>
          <MagnifyingGlassIcon style={{ width: '16px', height: '16px', color: 'var(--text-muted)', position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          <input 
            type="text"
            placeholder="SEARCH INTEL LOGS..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '0.4375rem 0.75rem 0.4375rem 2.25rem',
              backgroundColor: '#141414',
              border: '1px solid var(--border-color)',
              borderRadius: '0.25rem',
              fontSize: '0.75rem',
              color: '#ffffff',
              fontFamily: 'var(--font-mono)',
              outline: 'none'
            }}
          />
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', overflowX: 'auto', paddingBottom: '0.75rem', marginBottom: '1rem', borderBottom: '1px solid #262626' }}>
        {['all', 'critical', 'high', 'medium', 'low', 'info', 'passed'].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            style={{
              padding: '0.375rem 0.75rem',
              borderRadius: '0.125rem',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: 'pointer',
              border: '1px solid',
              backgroundColor: filterSeverity === sev ? '#262626' : '#141414',
              borderColor: filterSeverity === sev ? '#525252' : 'var(--border-color)',
              color: filterSeverity === sev ? '#ffffff' : 'var(--text-secondary)',
              fontFamily: 'var(--font-mono)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.375rem'
            }}
          >
            <span style={{ textTransform: 'uppercase' }}>
              {sev === 'critical' ? 'DEFCON 1 (CRITICAL)' : (sev === 'high' ? 'DEFCON 2 (HIGH)' : (sev === 'medium' ? 'DEFCON 3 (MED)' : (sev === 'passed' ? 'DEFCON 5 (PASS)' : sev.toUpperCase())))}
            </span>
            <span style={{ 
              background: '#0a0a0a', 
              padding: '0.0625rem 0.375rem', 
              borderRadius: '0.125rem', 
              fontSize: '0.6875rem' 
            }}>
              {severityCounts[sev]}
            </span>
          </button>
        ))}
      </div>

      {/* Findings Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.6875rem', letterSpacing: '0.05em', fontFamily: 'var(--font-mono)' }}>
              <th style={{ padding: '0.75rem 1rem' }}>THREAT LEVEL</th>
              <th style={{ padding: '0.75rem 1rem' }}>SECTOR MODULE</th>
              <th style={{ padding: '0.75rem 1rem' }}>TACTICAL VULNERABILITY MESSAGE</th>
              <th style={{ padding: '0.75rem 1rem' }}>TIMESTAMP</th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>TELEMETRY</th>
            </tr>
          </thead>
          <tbody>
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  NO VULNERABILITIES DETECTED MATCHING CURRENT FILTER CRITERIA.
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => (
                <tr 
                  key={finding.id}
                  style={{ borderBottom: '1px solid #262626' }}
                >
                  <td style={{ padding: '0.75rem 1rem', whiteSpace: 'nowrap' }}>
                    <span className={`badge ${getBadgeClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }}>
                    {finding.moduleName || finding.module}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: '#e5e5e5' }}>
                    {finding.message}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {finding.timestamp}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                    <button
                      onClick={() => setSelectedFinding(finding)}
                      className="btn btn-secondary"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.6875rem' }}
                    >
                      <span>TELEMETRY</span>
                      <ChevronRightIcon style={{ width: '12px', height: '12px' }} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Inspection Modal */}
      {selectedFinding && (
        <div className="modal-backdrop" onClick={() => setSelectedFinding(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <div>
                <span className={`badge ${getBadgeClass(selectedFinding.severity)}`}>
                  {selectedFinding.severity}
                </span>
                <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.125rem', fontWeight: 700, color: '#ffffff', marginTop: '0.5rem' }}>
                  {selectedFinding.message}
                </h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                  SECTOR: {selectedFinding.moduleName} • TELEMETRY STAMP: {selectedFinding.timestamp}
                </p>
              </div>
              <button 
                onClick={() => setSelectedFinding(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '0.25rem' }}
              >
                <XMarkIcon style={{ width: '20px', height: '20px' }} />
              </button>
            </div>

            {/* Finding Payload Details */}
            {selectedFinding.details && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
                
                {selectedFinding.details.recommendation && (
                  <div style={{ background: '#141414', border: '1px solid #333333', padding: '0.875rem', borderRadius: '0.25rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#16a34a', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'var(--font-mono)' }}>
                      TACTICAL REMEDIATION DIRECTIVE:
                    </span>
                    <p style={{ fontSize: '0.8125rem', color: '#e5e5e5', marginTop: '0.25rem' }}>
                      {selectedFinding.details.recommendation}
                    </p>
                  </div>
                )}

                <div>
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.375rem', fontFamily: 'var(--font-mono)' }}>
                    <CodeBracketIcon style={{ width: '16px', height: '16px' }} />
                    RAW THREAT PAYLOAD TELEMETRY:
                  </span>
                  <pre style={{ 
                    background: '#050505', 
                    border: '1px solid #262626', 
                    borderRadius: '0.25rem', 
                    padding: '1rem', 
                    fontSize: '0.75rem', 
                    fontFamily: 'var(--font-mono)', 
                    color: '#d4d4d4', 
                    marginTop: '0.5rem', 
                    overflowX: 'auto',
                    maxHeight: '260px'
                  }}>
                    {JSON.stringify(selectedFinding.details, null, 2)}
                  </pre>
                </div>

              </div>
            )}

            <div style={{ marginTop: '1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setSelectedFinding(null)}>
                CLOSE TELEMETRY
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
