import React from 'react';
import { 
  CheckIcon, 
  PlayIcon, 
  AdjustmentsHorizontalIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/solid';

export default function ModuleGrid({ modules, onToggleModule, onToggleAll, onRunModule, isScanning }) {
  const allSelected = modules.every(m => m.selected);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      
      {/* Module Section Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.125rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem', letterSpacing: '0.05em' }}>
            <ShieldCheckIcon style={{ width: '20px', height: '20px', color: '#16a34a' }} />
            TARGET THREAT VECTORS // 12 TACTICAL SECTORS
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.125rem', fontFamily: 'var(--font-mono)' }}>
            SELECT SECURITY DOMAINS FOR BATTLE-STATION PROBE EXECUTION
          </p>
        </div>

        <button 
          className="btn btn-secondary"
          onClick={onToggleAll}
          style={{ fontSize: '0.75rem', padding: '0.375rem 0.75rem' }}
        >
          <AdjustmentsHorizontalIcon style={{ width: '14px', height: '14px' }} />
          <span>{allSelected ? 'DISABLE ALL SECTORS' : 'ARM ALL 12 SECTORS'}</span>
        </button>
      </div>

      {/* Grid of 12 Sectors */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
        {modules.map((mod, index) => (
          <div 
            key={mod.id}
            style={{
              background: mod.selected ? '#141414' : '#0a0a0a',
              border: `1px solid ${mod.selected ? '#333333' : '#1a1a1a'}`,
              borderRadius: '0.25rem',
              padding: '1rem',
              display: 'flex',
              flexDirection: 'column',
              justify: 'space-between'
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                  {/* Tactical Checkbox */}
                  <div 
                    onClick={() => onToggleModule(mod.id)}
                    style={{
                      width: '18px',
                      height: '18px',
                      borderRadius: '0.125rem',
                      border: `1px solid ${mod.selected ? '#16a34a' : '#333333'}`,
                      backgroundColor: mod.selected ? '#16a34a' : 'transparent',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      cursor: 'pointer',
                      flexShrink: 0
                    }}
                  >
                    {mod.selected && <CheckIcon style={{ width: '14px', height: '14px', color: '#ffffff', strokeWidth: 3 }} />}
                  </div>

                  <h3 style={{ fontSize: '0.875rem', fontWeight: 700, color: mod.selected ? '#ffffff' : 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    SECTOR {String(index + 1).padStart(2, '0')}: {mod.name.toUpperCase()}
                  </h3>
                </div>

                <span style={{ 
                  fontFamily: 'var(--font-mono)', 
                  fontSize: '0.6875rem', 
                  color: '#a3a3a3', 
                  background: '#262626', 
                  padding: '0.125rem 0.375rem', 
                  borderRadius: '0.125rem' 
                }}>
                  {mod.code}
                </span>
              </div>

              <p style={{ fontSize: '0.78125rem', color: 'var(--text-secondary)', marginTop: '0.625rem', lineHeight: 1.4 }}>
                {mod.description}
              </p>
            </div>

            <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid #262626', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {mod.owasp}
              </span>

              <button 
                onClick={() => onRunModule(mod.id)}
                disabled={isScanning}
                className="btn btn-secondary"
                style={{ fontSize: '0.6875rem', padding: '0.25rem 0.5rem' }}
                title={`Deploy probe for ${mod.name}`}
              >
                <PlayIcon style={{ width: '12px', height: '12px', color: '#16a34a' }} />
                <span>DEPLOY PROBE</span>
              </button>
            </div>
          </div>
        ))}
      </div>

    </div>
  );
}
