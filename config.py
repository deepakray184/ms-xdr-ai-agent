"""Configuration management for Microsoft Defender XDR AI SOC Agent."""

import os
from typing import Optional
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv()


class Settings:
    # ----------------------------------------------------
    # Microsoft Entra ID & Defender XDR Graph API Settings
    # ----------------------------------------------------
    AZURE_TENANT_ID: Optional[str] = os.getenv("AZURE_TENANT_ID")
    AZURE_CLIENT_ID: Optional[str] = os.getenv("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET: Optional[str] = os.getenv("AZURE_CLIENT_SECRET")
    
    # Graph API endpoints & scopes
    GRAPH_API_BASE: str = os.getenv("GRAPH_API_BASE", "https://graph.microsoft.com/v1.0")
    GRAPH_SCOPE: str = os.getenv("GRAPH_SCOPE", "https://graph.microsoft.com/.default")
    
    # Flag to force simulation/mock mode (useful for testing without tenant access)
    # Automatically enabled if Azure credentials are missing
    @property
    def is_azure_configured(self) -> bool:
        return bool(
            self.AZURE_TENANT_ID 
            and self.AZURE_CLIENT_ID 
            and self.AZURE_CLIENT_SECRET
            and not self.AZURE_TENANT_ID.startswith("your-")
            and not self.AZURE_CLIENT_ID.startswith("your-")
        )
    
    FORCE_MOCK: bool = os.getenv("FORCE_MOCK", "false").lower() in ("true", "1", "yes")

    # ----------------------------------------------------
    # AI / LLM Engine Settings
    # ----------------------------------------------------
    # Options: "gemini", "openai", "claude", "azure_openai", "copilot", "ollama", "heuristic"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini").lower()
    
    # Google Gemini
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    
    # OpenAI / ChatGPT
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    OPENAI_BASE_URL: Optional[str] = os.getenv("OPENAI_BASE_URL")

    # Anthropic Claude
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-3-7-sonnet-20250219")
    
    # Azure OpenAI & Microsoft Copilot API Backend
    AZURE_OPENAI_API_KEY: Optional[str] = os.getenv("AZURE_OPENAI_API_KEY")
    AZURE_OPENAI_ENDPOINT: Optional[str] = os.getenv("AZURE_OPENAI_ENDPOINT")
    AZURE_OPENAI_DEPLOYMENT: Optional[str] = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")

    # Ollama / Local Models / Custom OpenAI-compatible endpoint
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.3")
    
    @property
    def is_llm_configured(self) -> bool:
        prov = self.LLM_PROVIDER
        if prov == "gemini":
            return bool(self.GEMINI_API_KEY and not self.GEMINI_API_KEY.startswith("your-"))
        elif prov in ("openai", "chatgpt"):
            return bool(self.OPENAI_API_KEY and not self.OPENAI_API_KEY.startswith("your-"))
        elif prov in ("claude", "anthropic"):
            return bool(self.ANTHROPIC_API_KEY and not self.ANTHROPIC_API_KEY.startswith("your-"))
        elif prov in ("azure_openai", "copilot", "ms_copilot"):
            return bool(self.AZURE_OPENAI_API_KEY and self.AZURE_OPENAI_ENDPOINT)
        elif prov in ("ollama", "local", "custom"):
            return True
        return False

    # ----------------------------------------------------
    # Dashboard / Server Settings
    # ----------------------------------------------------
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))


settings = Settings()
