import React, { useEffect, useRef } from 'react';
import { CommandLineIcon, TrashIcon } from '@heroicons/react/24/outline';

export default function TerminalConsole({ logs, onClearLogs }) {
  const terminalEndRef = useRef(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView();
  }, [logs]);

  return (
    <div className="terminal-window">
      
      {/* Terminal Title Bar */}
      <div className="terminal-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <CommandLineIcon style={{ width: '16px', height: '16px', color: '#16a34a' }} />
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
            STRATEGIC OPERATIONS CONSOLE // REAL-TIME PROBE FEED
          </span>
        </div>

        <button 
          onClick={onClearLogs} 
          style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.6875rem', fontFamily: 'var(--font-mono)' }}
          title="Clear console output"
        >
          <TrashIcon style={{ width: '12px', height: '12px' }} />
          CLEAR CONSOLE
        </button>
      </div>

      {/* Terminal Body */}
      <div className="terminal-body">
        {logs.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontStyle: 'italic', fontFamily: 'var(--font-mono)' }}>
            Operations log ready. Click "ENGAGE FULL SUITE" or deploy sector probes to stream tactical output.
          </div>
        ) : (
          logs.map((log, index) => (
            <div key={index} className={`terminal-line ${log.type || 'info'}`}>
              <span style={{ opacity: 0.5, marginRight: '0.5rem' }}>[{log.time}]</span>
              <span>{log.text}</span>
            </div>
          ))
        )}
        <div ref={terminalEndRef} />
      </div>

    </div>
  );
}
