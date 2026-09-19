import React, { useState } from 'react';
import { Cog6ToothIcon, XMarkIcon, KeyIcon, GlobeAltIcon } from '@heroicons/react/24/outline';

export default function ConfigModal({ config, onSave, onClose }) {
  const [formData, setFormData] = useState({ ...config });

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave(formData);
    onClose();
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ padding: '1.5rem' }}>
        
        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <Cog6ToothIcon style={{ width: '22px', height: '22px', color: '#16a34a' }} />
            <div>
              <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: '1.125rem', fontWeight: 800, color: '#ffffff', letterSpacing: '0.05em' }}>
                SITUATION ROOM // CONFIGURATION LAB
              </h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                CONFIGURE TARGET BASE COORD AND ROLE AUTHENTICATION TOKENS
              </p>
            </div>
          </div>

          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <XMarkIcon style={{ width: '20px', height: '20px' }} />
          </button>
        </div>

        {/* Configuration Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          
          {/* Target Base URL */}
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.375rem', fontFamily: 'var(--font-mono)' }}>
              <GlobeAltIcon style={{ width: '16px', height: '16px', color: '#16a34a' }} />
              TARGET COORD BASE URL
            </label>
            <input 
              type="text"
              name="base_url"
              value={formData.base_url}
              onChange={handleChange}
              placeholder="http://127.0.0.1:8000"
              required
              style={{
                width: '100%',
                padding: '0.5rem 0.75rem',
                backgroundColor: '#0a0a0a',
                border: '1px solid var(--border-color)',
                borderRadius: '0.25rem',
                fontSize: '0.8125rem',
                color: '#f5f5f5',
                fontFamily: 'var(--font-mono)',
                outline: 'none'
              }}
            />
          </div>

          {/* Session Tokens Grid */}
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)' }}>
              <KeyIcon style={{ width: '16px', height: '16px', color: '#16a34a' }} />
              ROLE AUTHENTICATION TOKENS (`laravel_session` / JWT)
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>ADMIN SESSION KEY</span>
                <input 
                  type="text"
                  name="admin_session"
                  value={formData.admin_session || ''}
                  onChange={handleChange}
                  placeholder="admin_session_cookie"
                  style={{
                    width: '100%',
                    padding: '0.4375rem 0.625rem',
                    backgroundColor: '#0a0a0a',
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.25rem',
                    fontSize: '0.75rem',
                    color: '#ffffff',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '0.25rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>USER A SESSION KEY</span>
                <input 
                  type="text"
                  name="user_a_session"
                  value={formData.user_a_session || ''}
                  onChange={handleChange}
                  placeholder="user_a_session_cookie"
                  style={{
                    width: '100%',
                    padding: '0.4375rem 0.625rem',
                    backgroundColor: '#0a0a0a',
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.25rem',
                    fontSize: '0.75rem',
                    color: '#ffffff',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '0.25rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>USER B SESSION KEY</span>
                <input 
                  type="text"
                  name="user_b_session"
                  value={formData.user_b_session || ''}
                  onChange={handleChange}
                  placeholder="user_b_session_cookie"
                  style={{
                    width: '100%',
                    padding: '0.4375rem 0.625rem',
                    backgroundColor: '#0a0a0a',
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.25rem',
                    fontSize: '0.75rem',
                    color: '#ffffff',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '0.25rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>TENANT A SESSION KEY</span>
                <input 
                  type="text"
                  name="agency_a_session"
                  value={formData.agency_a_session || ''}
                  onChange={handleChange}
                  placeholder="agency_a_session_cookie"
                  style={{
                    width: '100%',
                    padding: '0.4375rem 0.625rem',
                    backgroundColor: '#0a0a0a',
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.25rem',
                    fontSize: '0.75rem',
                    color: '#ffffff',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '0.25rem',
                    outline: 'none'
                  }}
                />
              </div>

            </div>
          </div>

          {/* Timeout & Delay Controls */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>REQUEST TIMEOUT (SEC)</label>
              <input 
                type="number"
                name="request_timeout"
                value={formData.request_timeout}
                onChange={handleChange}
                style={{
                  width: '100%',
                  padding: '0.4375rem 0.625rem',
                  backgroundColor: '#0a0a0a',
                  border: '1px solid var(--border-color)',
                  borderRadius: '0.25rem',
                  fontSize: '0.75rem',
                  color: '#ffffff',
                  fontFamily: 'var(--font-mono)',
                  marginTop: '0.25rem',
                  outline: 'none'
                }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>PROBE DELAY (SEC)</label>
              <input 
                type="number"
                step="0.05"
                name="request_delay"
                value={formData.request_delay}
                onChange={handleChange}
                style={{
                  width: '100%',
                  padding: '0.4375rem 0.625rem',
                  backgroundColor: '#0a0a0a',
                  border: '1px solid var(--border-color)',
                  borderRadius: '0.25rem',
                  fontSize: '0.75rem',
                  color: '#ffffff',
                  fontFamily: 'var(--font-mono)',
                  marginTop: '0.25rem',
                  outline: 'none'
                }}
              />
            </div>
          </div>

          {/* AI Pentest Agents Section */}
          <div style={{ borderTop: '1px solid #262626', paddingTop: '0.875rem', marginTop: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
              <div>
                <span style={{ fontSize: '0.8125rem', fontWeight: 800, color: '#f5f5f5', fontFamily: 'var(--font-mono)' }}>
                  🤖 AI PENTEST AGENTS & ETHICAL HACKERS
                </span>
                <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', margin: 0 }}>
                  Enable autonomous LLM pentest agents for OpenAI, Claude, or Gemini
                </p>
              </div>

              <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input 
                  type="checkbox"
                  name="ai_agents_enabled"
                  checked={formData.ai_agents_enabled || false}
                  onChange={handleChange}
                  style={{ width: '16px', height: '16px', accentColor: '#16a34a' }}
                />
                <span style={{ fontSize: '0.75rem', color: formData.ai_agents_enabled ? '#4ade80' : 'var(--text-muted)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                  {formData.ai_agents_enabled ? 'ENABLED' : 'DISABLED'}
                </span>
              </label>
            </div>

            {formData.ai_agents_enabled && (
              <div style={{ background: '#0a0a0a', padding: '0.875rem', borderRadius: '0.25rem', border: '1px solid #262626', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div>
                    <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: '0.25rem' }}>LLM PROVIDER</label>
                    <select 
                      name="ai_provider"
                      value={formData.ai_provider || 'openai'}
                      onChange={(e) => {
                        const prov = e.target.value;
                        const defaultModels = { openai: 'gpt-4o', anthropic: 'claude-3-5-sonnet-20241022', google: 'gemini-2.0-flash' };
                        setFormData(prev => ({ ...prev, ai_provider: prov, ai_model: defaultModels[prov] || 'gpt-4o' }));
                      }}
                      style={{ width: '100%', padding: '0.4375rem', backgroundColor: '#141414', border: '1px solid #333', borderRadius: '0.25rem', color: '#fff', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
                    >
                      <option value="openai">OpenAI (ChatGPT)</option>
                      <option value="anthropic">Anthropic (Claude)</option>
                      <option value="google">Google (Gemini)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: '0.25rem' }}>TARGET MODEL</label>
                    <select 
                      name="ai_model"
                      value={formData.ai_model || 'gpt-4o'}
                      onChange={handleChange}
                      style={{ width: '100%', padding: '0.4375rem', backgroundColor: '#141414', border: '1px solid #333', borderRadius: '0.25rem', color: '#fff', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
                    >
                      {formData.ai_provider === 'openai' && (
                        <>
                          <option value="gpt-4o">GPT-4o (Strongest Flagship)</option>
                          <option value="o3-mini">o3-mini (High Reasoning)</option>
                          <option value="gpt-4o-mini">GPT-4o Mini (Mid Tier)</option>
                        </>
                      )}
                      {formData.ai_provider === 'anthropic' && (
                        <>
                          <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet (Strongest)</option>
                          <option value="fable-5-1">Fable 5.1 (Mid/High Reasoning)</option>
                          <option value="claude-3-5-haiku-20241022">Claude 3.5 Haiku (Mid Tier)</option>
                        </>
                      )}
                      {formData.ai_provider === 'google' && (
                        <>
                          <option value="gemini-3-6-high">Gemini 3.6 High (Strongest Ultra)</option>
                          <option value="gemini-2-0-flash">Gemini 2.0 Flash (Fast Mid/High)</option>
                          <option value="astra-pentest">Astra (Cyber Intelligence Model)</option>
                        </>
                      )}
                    </select>
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: '0.25rem' }}>PROVIDER API KEY (OPTIONAL - SIMULATED IF BLANK)</label>
                  <input 
                    type="password"
                    name="ai_api_key"
                    value={formData.ai_api_key || ''}
                    onChange={handleChange}
                    placeholder="sk-..."
                    style={{ width: '100%', padding: '0.4375rem', backgroundColor: '#141414', border: '1px solid #333', borderRadius: '0.25rem', color: '#fff', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
                  />
                </div>

              </div>
            )}
          </div>

          {/* Form Actions */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1rem', marginTop: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              ABORT
            </button>
            <button type="submit" className="btn btn-primary">
              SAVE PARAMS
            </button>
          </div>

        </form>

      </div>
    </div>
  );
}
