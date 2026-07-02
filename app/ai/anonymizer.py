import re
import os
import json
from typing import Any


class PIIAnonymizer:
    """Proxy de anonimizacao inspirado no DontFeedTheAI.
    Stripa PII antes de enviar ao LLM (Groq) e restaura no response.
    """

    def __init__(self, vault_path: str | None = None):
        self._mapping: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counter = 0
        self._vault_path = vault_path

        self._patterns = [
            ('IP_V4', r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            ('HOSTNAME', r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            ('EMAIL', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            ('API_KEY', r'\b(?:sk-[A-Za-z0-9]{32,}|pk-[A-Za-z0-9]{32,}|[A-Za-z0-9]{32,45})\b'),
            ('URL_INTERNAL', r'\b(?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]\d{0,2}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?\b'),
            ('JWT_TOKEN', r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
            ('CREDIT_CARD', r'\b(?:\d[ -]*?){13,16}\b'),
            ('PASSWORD', r'(?i)(?:password|senha|secret|passwd|pwd)\s*[:=]\s*["\']?[^\s"\'&]{4,}["\']?'),
            ('AWS_KEY', r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
            ('PRIVATE_KEY', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
            ('INTERNAL_PATH', r'\b(?:/home/|/Users/|/root/|/var/www/|C:\\|/app/)[^\s]*\b'),
        ]

    def anonymize(self, text: str) -> str:
        """Substitui PII por placeholders seguros."""
        for label, pattern in self._patterns:
            def replacer(m: re.Match, lbl: str = label) -> str:
                return self._replace_match(lbl, m.group(0))
            text = re.sub(pattern, replacer, text)
        return text

    def _replace_match(self, label: str, value: str) -> str:
        if value in self._reverse:
            return self._reverse[value]

        placeholder = f'___{label}_{self._counter}___'
        self._counter += 1
        self._mapping[placeholder] = value
        self._reverse[value] = placeholder
        return placeholder

    def restore(self, text: str) -> str:
        """Restaura placeholders para valores originais."""
        for placeholder, original in self._mapping.items():
            text = text.replace(placeholder, original)
        return text

    def anonymize_prompt(self, system_prompt: str, user_prompt: str) -> tuple[str, str]:
        """Anonimiza ambos os lados do prompt."""
        return self.anonymize(system_prompt), self.anonymize(user_prompt)

    def restore_response(self, response: str) -> str:
        """Restaura valores originais na resposta do LLM."""
        return self.restore(response)

    def save_vault(self, engagement_id: str | None = None):
        """Salva o vault de mapeamento para auditoria e restauracao futura."""
        if not self._vault_path:
            return
        eid = engagement_id or 'default'
        vault_file = os.path.join(self._vault_path, f'vault_{eid}.json')
        os.makedirs(self._vault_path, exist_ok=True)
        with open(vault_file, 'w') as f:
            json.dump({'mapping': self._mapping, 'engagement': eid}, f, indent=2)

    def clear(self):
        """Limpa o vault em memoria."""
        self._mapping.clear()
        self._reverse.clear()
        self._counter = 0


_anonymizer: PIIAnonymizer | None = None


def get_anonymizer(vault_path: str | None = None) -> PIIAnonymizer:
    global _anonymizer
    if _anonymizer is None:
        vp = vault_path or os.environ.get('JAIZZ_VAULT_PATH')
        _anonymizer = PIIAnonymizer(vault_path=vp)
    return _anonymizer
