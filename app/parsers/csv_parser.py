import csv
import io

class CSVParser:
    """
    Parser genérico para interpretar outputs em formato CSV.
    """

    def __init__(self, raw_data, plugin_name, project_id):
        self.raw_data = raw_data
        self.plugin_name = plugin_name
        self.project_id = project_id
        self.findings = []

    def parse(self, mapping_rules):
        """
        mapping_rules = {
            "title_column": "Name",          # Nome da coluna que tem o título
            "description_column": "Details", # Nome da coluna que tem a descrição
            "severity_column": "Risk"        # Nome da coluna que tem a severidade
        }
        """
        try:
            # Se for string (ex: lido de um arquivo ou stdout)
            if isinstance(self.raw_data, str):
                f = io.StringIO(self.raw_data)
                reader = csv.DictReader(f)
            else:
                return []

            for row in reader:
                # O DictReader converte cada linha num dicionário onde a chave é a coluna
                finding = {
                    "project_id": self.project_id,
                    "plugin_source": self.plugin_name,
                    "title": row.get(mapping_rules.get("title_column", "title"), "Vulnerabilidade CSV"),
                    "description": row.get(mapping_rules.get("description_column", "description"), "Sem descrição CSV."),
                    "severity": row.get(mapping_rules.get("severity_column", "severity"), "Info"),
                    "raw_data": row  # Guardamos a linha inteira como JSON na coluna raw_data
                }
                self.findings.append(finding)

            return self.findings

        except Exception as e:
            print(f"[CSVParser] Erro genérico: {e}")
            return []
