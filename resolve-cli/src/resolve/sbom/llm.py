"""Handles conversion from CVEs to Vulnerability JSON format"""
from __future__ import absolute_import

class LLMError(BaseException):
    pass
    
class AffectedNotFoundError(LLMError):
    pass

class LLM:
    prompt = "The following text describes a CVE. If it specifies which file and function are vulnerable, reply in the format file:function. Othewise, if this is not readily apparent, reply 'N/A'. "
    
    def _query(self, payload : str) -> str:
        raise NotImplementedError
        
    def get_affected(self, description: str) -> tuple[str, str]:
        payload = self.prompt + description
        try:
            response = self._query(payload).strip()
        except LLMError as e:
            raise e
        except BaseException as e:
            raise LLMError from e
        if response == 'N/A':
            raise AffectedNotFoundError
        sp = response.split(':')
        if len(sp) != 2:
            raise LLMError(f"Invalid LLM response: '{sp}'")
        return (sp[0], sp[1])
        
        
class Ollama(LLM):
    def __init__(self, model = 'gemma3', server = 'http://localhost:11434'):
        import requests
        self.requests = requests
        self.model = model
        self.api_base = server + "/api/generate"
        
    def _query(self, payload: str) -> str:
        params = {"model": self.model, "prompt": payload}
        resp = self.requests.get(self.api_base, params=params)
        resp.raise_for_status()
        return resp.json()['message']['content']
        
        
class Gemini(LLM):
    def __init__(self, model = 'gemini-2.5-flash', **kwargs) -> None:
        from google import genai
        self.client = genai.Client(**kwargs)
        self.model = model
        
    def _query(self, payload: str) -> str:
        resp = self.client.models.generate_content(model=self.model, contents=payload).text
        if not resp:
            raise LLMError("Empty response")
        return resp