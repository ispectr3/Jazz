import json
from datetime import datetime

class JSONParser:
    """
    Parser genérico para interpretar outputs em formato JSON de ferramentas de segurança.
    Converte os dados brutos (raw JSON) em dicionários normalizados prontos
    para serem inseridos no banco de dados como objetos 'Finding'.
    """

    def __init__(self, raw_data, plugin_name, project_id):
        self.raw_data = raw_data
        self.plugin_name = plugin_name
        self.project_id = project_id
        self.findings = []

    def parse(self, mapping_rules):
        """
        Interpreta o JSON com base em um dicionário de regras de mapeamento.
        
        mapping_rules = {
            "iterator_key": "vulnerabilities", # Qual lista do JSON vamos iterar?
            "title_key": "name",               # Chave para o título da vulnerabilidade
            "description_key": "desc",         # Chave para a descrição
            "severity_key": "risk"             # Chave para a severidade
        }
        """
        try:
            # Se for string (conteúdo lido de um arquivo), fazemos o load
            if isinstance(self.raw_data, str):
                data = json.loads(self.raw_data)
            else:
                data = self.raw_data

            # Se o JSON for uma lista direta ou se estiver dentro de uma chave específica
            iterator_key = mapping_rules.get("iterator_key")
            items = data.get(iterator_key, []) if iterator_key else data

            # Garante que temos uma lista para iterar
            if not isinstance(items, list):
                items = [items]

            for item in items:
                finding = {
                    "project_id": self.project_id,
                    "plugin_source": self.plugin_name,
                    "title": item.get(mapping_rules.get("title_key", "title"), "Vulnerabilidade Desconhecida"),
                    "description": item.get(mapping_rules.get("description_key", "description"), "Sem descrição fornecida."),
                    "severity": item.get(mapping_rules.get("severity_key", "severity"), "Info"),
                    "raw_data": item  # Guardamos a evidência bruta do item isolado
                }
                self.findings.append(finding)

            return self.findings

        except json.JSONDecodeError as e:
            print(f"[JSONParser] Erro ao decodificar JSON do plugin {self.plugin_name}: {e}")
            return []
        except Exception as e:
            print(f"[JSONParser] Erro inesperado no parser: {e}")
            return []
