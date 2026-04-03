"""Handles conversion from CVEs to Vulnerability JSON format"""
from __future__ import absolute_import

class LLMError(BaseException):
    pass
    
class AffectedNotFoundError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass

class APIKeyError(LLMError):
    pass

class LLM:
    prompt: str = "The following text describes a CVE. If it specifies which file and function is vulnerable, reply in the exact format `{file name}:{function name}` Otherwise, if this is not readily apparent, reply `N/A`. "
    
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
    def __init__(self, model: str = 'gemma3', server: str = 'http://localhost:11434'):
        import ollama
        self.api = ollama.generate
        self.model = model            
        
    def _query(self, payload: str) -> str:
        resp = self.api(self.model, payload)
        return resp.response        
        
class Gemini(LLM):
    def __init__(self, model: str = 'gemini-2.5-flash', **kwargs) -> None:
        from google import genai
        try:
            self.client = genai.Client(**kwargs)
        except ValueError as e:
            raise APIKeyError() from e
        self.model = model
        
    def _query(self, payload: str) -> str:
        resp = self.client.models.generate_content(model=self.model, contents=payload).text
        if not resp:
            raise LLMError("Empty response")
        return resp
