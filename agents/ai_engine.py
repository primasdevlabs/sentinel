"""
Sentinel-12 AI Pentest Agent Engine
Supports OpenAI, Anthropic (Claude), and Google (Gemini) LLM providers
for AI-driven ethical hacking, exploit analysis, and security domain probing.
"""

import os
import json
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Any


class AIPentestEngine:
    """Unified LLM Provider Interface for AI Pentest Agents"""
    
    def __init__(self, provider: str = "openai", api_key: Optional[str] = None, model: Optional[str] = None):
        self.provider = (provider or "openai").lower()
        self.api_key = api_key or self._get_env_key(self.provider)
        self.model = model or self._default_model(self.provider)

    def _get_env_key(self, provider: str) -> Optional[str]:
        if provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif provider == "anthropic" or provider == "claude":
            return os.getenv("ANTHROPIC_API_KEY")
        elif provider == "google" or provider == "gemini":
            return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        return None

    def _default_model(self, provider: str) -> str:
        if provider == "openai":
            return "gpt-5"
        elif provider in ("anthropic", "claude"):
            return "claude-fable"
        elif provider in ("google", "gemini"):
            return "gemini-3-8-flash"
        return "gpt-5"

    def _resolve_api_model(self, provider: str, model: str) -> str:
        """Map user-selected catalog model aliases to active API model endpoints"""
        m = (model or "").lower().strip()
        if provider == "openai":
            aliases = {
                "gpt-5": "gpt-4o",
                "gpt-5-mini": "gpt-4o-mini",
                "gpt-5-nano": "gpt-4o-mini",
                "gpt-4.1": "gpt-4o",
                "gpt-4.1-mini": "gpt-4o-mini",
                "gpt-4.1-nano": "gpt-4o-mini",
                "gpt-4o": "gpt-4o",
                "gpt-4o-mini": "gpt-4o-mini"
            }
            return aliases.get(m, model)
        elif provider in ("anthropic", "claude"):
            aliases = {
                "claude-fable": "claude-3-5-sonnet-20241022",
                "claude-opus": "claude-3-5-sonnet-20241022",
                "claude-sonnet": "claude-3-5-sonnet-20241022",
                "claude-haiku": "claude-3-5-haiku-20241022"
            }
            return aliases.get(m, model)
        elif provider in ("google", "gemini"):
            aliases = {
                "gemini-3-8-flash": "gemini-2.0-flash",
                "gemini-3-8-live": "gemini-2.0-flash",
                "gemini-3-8-live-extended-thinking": "gemini-2.0-flash",
                "gemini-3-7-flash": "gemini-2.0-flash",
                "gemini-3-6-flash": "gemini-2.0-flash",
                "gemini-3-5-flash": "gemini-2.0-flash"
            }
            return aliases.get(m, model)
        return model

    def execute_prompt(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """Execute prompt against configured provider"""
        if not self.api_key:
            # Fallback simulated AI Pentest response if API key is not supplied
            return {
                "status": "simulated",
                "provider": self.provider,
                "model": self.model,
                "analysis": f"[AI PENTESTER] Analysis simulated (No API key provided for {self.provider.upper()}).\n"
                            f"Target evaluation completed for prompt vector: '{user_prompt[:80]}...'\n"
                            f"Enforce strict input validation, authorization bounds, and session token checks."
            }

        try:
            if self.provider == "openai":
                return self._call_openai(system_prompt, user_prompt)
            elif self.provider in ("anthropic", "claude"):
                return self._call_anthropic(system_prompt, user_prompt)
            elif self.provider in ("google", "gemini"):
                return self._call_gemini(system_prompt, user_prompt)
            else:
                return self._call_openai(system_prompt, user_prompt)
        except Exception as e:
            return {
                "status": "error",
                "provider": self.provider,
                "model": self.model,
                "error": str(e),
                "analysis": f"[AI PENTEST ERROR] Provider {self.provider} request failed: {e}"
            }

    def _call_openai(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        url = "https://api.openai.com/v1/chat/completions"
        api_model = self._resolve_api_model("openai", self.model)
        payload = {
            "model": api_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            analysis = data['choices'][0]['message']['content']
            return {"status": "success", "provider": "openai", "model": self.model, "analysis": analysis}

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        url = "https://api.anthropic.com/v1/messages"
        api_model = self._resolve_api_model("anthropic", self.model)
        payload = {
            "model": api_model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt}
            ]
        }
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01"
        }

        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            analysis = data['content'][0]['text']
            return {"status": "success", "provider": "anthropic", "model": self.model, "analysis": analysis}

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        api_model = self._resolve_api_model("google", self.model)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{api_model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"System Directive: {system_prompt}\n\nTask Directive: {user_prompt}"}
                    ]
                }
            ]
        }
        headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            analysis = data['candidates'][0]['content']['parts'][0]['text']
            return {"status": "success", "provider": "gemini", "model": self.model, "analysis": analysis}
