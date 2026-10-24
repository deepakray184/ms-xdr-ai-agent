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
    # Options: "gemini", "openai", "azure_openai", "heuristic"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini").lower()
    
    # Google Gemini
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    
    # OpenAI
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    OPENAI_BASE_URL: Optional[str] = os.getenv("OPENAI_BASE_URL")
    
    # Azure OpenAI
    AZURE_OPENAI_API_KEY: Optional[str] = os.getenv("AZURE_OPENAI_API_KEY")
    AZURE_OPENAI_ENDPOINT: Optional[str] = os.getenv("AZURE_OPENAI_ENDPOINT")
    AZURE_OPENAI_DEPLOYMENT: Optional[str] = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    AZURE_OPENAI_API_VERSION: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
    
    @property
    def is_llm_configured(self) -> bool:
        if self.LLM_PROVIDER == "gemini":
            return bool(self.GEMINI_API_KEY and not self.GEMINI_API_KEY.startswith("your-"))
        elif self.LLM_PROVIDER == "openai":
            return bool(self.OPENAI_API_KEY and not self.OPENAI_API_KEY.startswith("your-"))
        elif self.LLM_PROVIDER == "azure_openai":
            return bool(self.AZURE_OPENAI_API_KEY and self.AZURE_OPENAI_ENDPOINT)
        return False

    # ----------------------------------------------------
    # Dashboard / Server Settings
    # ----------------------------------------------------
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))


settings = Settings()
