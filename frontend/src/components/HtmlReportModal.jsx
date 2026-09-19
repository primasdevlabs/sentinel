import React from 'react';
import { DocumentChartBarIcon, XMarkIcon, ArrowTopRightOnSquareIcon } from '@heroicons/react/24/outline';

export default function HtmlReportModal({ htmlContent, onClose }) {
  const handleOpenNewTab = () => {
    const win = window.open('', '_blank');
    if (win) {
      win.document.write(htmlContent);
      win.document.close();
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '1000px', width: '95%', height: '85vh' }}>
        
        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <DocumentChartBarIcon style={{ width: '22px', height: '22px', color: '#16a34a' }} />
            <div>
              <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.125rem', fontWeight: 800, color: '#ffffff', letterSpacing: '0.05em' }}>
                DIRECT HTML REPORT PREVIEW
              </h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                DEFCON 1 SITUATION ROOM AUDIT DASHBOARD
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button 
              onClick={handleOpenNewTab}
              className="btn btn-secondary"
              style={{ fontSize: '0.75rem', padding: '0.375rem 0.75rem' }}
              title="Open full page report in new browser tab"
            >
              <ArrowTopRightOnSquareIcon style={{ width: '14px', height: '14px' }} />
              <span>OPEN IN NEW TAB</span>
            </button>

            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '0.25rem' }}>
              <XMarkIcon style={{ width: '20px', height: '20px' }} />
            </button>
          </div>
        </div>

        {/* Modal Body: Embedded iframe previewing the HTML report live */}
        <div style={{ flex: 1, backgroundColor: '#0a0a0a', padding: 0, overflow: 'hidden' }}>
          <iframe 
            srcDoc={htmlContent}
            title="HTML Audit Report Preview"
            style={{ width: '100%', height: '100%', border: 'none' }}
          />
        </div>

        {/* Footer */}
        <div style={{ borderTop: '1px solid var(--border-color)', padding: '0.75rem 1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn btn-secondary" onClick={onClose}>
            CLOSE PREVIEW
          </button>
        </div>

      </div>
    </div>
  );
}
