import React, { useState } from 'react';
import { CodeBracketIcon, XMarkIcon, ClipboardDocumentIcon, CheckIcon } from '@heroicons/react/24/outline';

export default function JsonViewerModal({ reportData, onClose }) {
  const [copied, setCopied] = useState(false);
  const jsonString = JSON.stringify(reportData, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '800px', width: '90%' }}>
        
        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <CodeBracketIcon style={{ width: '22px', height: '22px', color: '#16a34a' }} />
            <div>
              <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.125rem', fontWeight: 800, color: '#ffffff', letterSpacing: '0.05em' }}>
                CLASSIFIED JSON INTEL REPORT
              </h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                DIRECT VIEW // LIVE JSON TELEMETRY SCHEMA
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button 
              onClick={handleCopy}
              className="btn btn-secondary"
              style={{ fontSize: '0.75rem', padding: '0.375rem 0.75rem' }}
            >
              {copied ? (
                <>
                  <CheckIcon style={{ width: '14px', height: '14px', color: '#16a34a' }} />
                  <span>COPIED</span>
                </>
              ) : (
                <>
                  <ClipboardDocumentIcon style={{ width: '14px', height: '14px' }} />
                  <span>COPY JSON</span>
                </>
              )}
            </button>

            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '0.25rem' }}>
              <XMarkIcon style={{ width: '20px', height: '20px' }} />
            </button>
          </div>
        </div>

        {/* Modal Content */}
        <div style={{ padding: '1.5rem' }}>
          <pre style={{ 
            background: '#050505', 
            border: '1px solid var(--border-color)', 
            borderRadius: '0.25rem', 
            padding: '1.25rem', 
            fontSize: '0.78125rem', 
            fontFamily: 'var(--font-mono)', 
            color: '#e5e5e5', 
            overflowX: 'auto',
            maxHeight: '500px',
            lineHeight: 1.5
          }}>
            {jsonString}
          </pre>
        </div>

        {/* Footer */}
        <div style={{ borderTop: '1px solid var(--border-color)', padding: '1rem 1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn btn-secondary" onClick={onClose}>
            CLOSE VIEWER
          </button>
        </div>

      </div>
    </div>
  );
}
