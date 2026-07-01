import xml.etree.ElementTree as ET

class XMLParser:
    """
    Parser genérico para interpretar outputs em formato XML de ferramentas de segurança.
    Útil para ferramentas como Nmap (saída -oX).
    """

    def __init__(self, raw_data, plugin_name, project_id):
        self.raw_data = raw_data
        self.plugin_name = plugin_name
        self.project_id = project_id
        self.findings = []

    def parse(self, mapping_rules):
        """
        mapping_rules = {
            "root_tag": "host",           # Qual tag representa um item/vulnerabilidade?
            "title_tag": "name",          # Qual tag filha tem o título?
            "description_tag": "desc",    # Qual tag filha tem a descrição?
            "severity_tag": "risk"        # Qual tag filha tem a severidade?
        }
        """
        try:
            # Tenta parsear como string se vier diretamente do output da ferramenta
            root = ET.fromstring(self.raw_data)
            
            root_tag = mapping_rules.get("root_tag")
            items = root.findall(f".//{root_tag}") if root_tag else [root]

            for item in items:
                title_elem = item.find(mapping_rules.get("title_tag", "title"))
                desc_elem = item.find(mapping_rules.get("description_tag", "description"))
                sev_elem = item.find(mapping_rules.get("severity_tag", "severity"))

                # Converte o XML element de volta pra string pra guardar a evidência
                raw_xml_string = ET.tostring(item, encoding='unicode')

                finding = {
                    "project_id": self.project_id,
                    "plugin_source": self.plugin_name,
                    "title": title_elem.text if title_elem is not None else "Vulnerabilidade XML",
                    "description": desc_elem.text if desc_elem is not None else "Sem descrição XML.",
                    "severity": sev_elem.text if sev_elem is not None else "Info",
                    "raw_data": {"xml_evidence": raw_xml_string}
                }
                self.findings.append(finding)

            return self.findings

        except ET.ParseError as e:
            print(f"[XMLParser] Erro de formatação XML no plugin {self.plugin_name}: {e}")
            return []
        except Exception as e:
            print(f"[XMLParser] Erro genérico: {e}")
            return []
