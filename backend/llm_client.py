import os
import json
import httpx
import config

class LLMClient:
    def __init__(self, mode: str = None):
        self.mode = mode or config.AGENT_MODE
        
    async def chat(self, messages: list) -> str:
        if self.mode == "gemini":
            return await self._call_gemini(messages)
        elif self.mode == "ollama":
            return await self._call_ollama(messages)
        else:
            raise ValueError(f"Unsupported LLM mode: {self.mode}")

    async def _call_gemini(self, messages: list) -> str:
        api_key = config.GEMINI_API_KEY
        if not api_key:
            raise ValueError("GEMINI_API_KEY not set")
            
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        # Convert standard OpenAI/Ollama messages to Gemini format
        gemini_messages = []
        system_instruction = ""
        for m in messages:
            if m["role"] == "system":
                system_instruction += m["content"] + "\n"
            else:
                role = "user" if m["role"] == "user" else "model"
                gemini_messages.append({"role": role, "parts": [{"text": m["content"]}]})
                
        payload = {
            "contents": gemini_messages,
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": {"temperature": 0.1} # low temp for deterministic JSON
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    async def _call_ollama(self, messages: list) -> str:
        payload = {
            "model": config.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1}
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(config.OLLAMA_URL, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
