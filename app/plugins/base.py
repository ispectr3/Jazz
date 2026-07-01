from abc import ABC, abstractmethod
from typing import Dict, Any, List

class ScannerAdapter(ABC):
    """
    Interface abstrata requerida para qualquer ferramenta de avaliação de segurança.
    Foco: Validação, Normalização e Log.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def validate_input(self, raw_data: str) -> bool:
        """Valida se o formato do arquivo/texto bate com o esperado pela ferramenta"""
        pass

    @abstractmethod
    def normalize(self, raw_data: str) -> List[Dict[str, Any]]:
        """
        Lê a saída da ferramenta e a converte em uma lista de dicionários,
        onde cada dicionário mapeia perfeitamente para o model 'Finding'.
        """
        pass

    def generate_log(self, status: str, details: str):
        """Método comum para registrar auditoria da execução do plugin"""
        # Futura integração com o modelo AuditLog
        print(f"[{self.name}] {status}: {details}")
