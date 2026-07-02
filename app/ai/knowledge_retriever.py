"""
knowledge_retriever.py — Sistema leve de RAG (Retrieval-Augmented Generation)
para enriquecer prompts do Claude-BugHunter com exemplos reais relevantes.

Funcionamento:
  1. Indexa a knowledge base (JSON + MD) em um dicionario de tags
  2. Recebe um finding (titulo + descricao) e identifica palavras-chave
  3. Recupera os N exemplos mais relevantes por scoring TF-IDF-like
  4. Retorna exemplos contextualizados para injecao no prompt

Nao requer:
  - sentence-transformers (pesado)
  - chroma/pinecone (infra externa)
  - GPU

Usa apenas:
  - re (regex para tokenizacao)
  - math (para IDF)
  - Colecoes Counter (frequencia)
"""
import json
import os
import re
import math
from collections import Counter
from typing import List, Dict, Optional

TOKEN_PATTERN = re.compile(r'[a-zA-Z]{3,}')

STOPWORDS = {
    "the", "this", "that", "with", "from", "have", "been", "were",
    "para", "com", "dos", "das", "uma", "como", "mais", "mas",
    "por", "que", "sao", "seu", "sua", "tem", "era", "sobre",
    "when", "what", "which", "where", "also", "than", "then",
    "will", "each", "other", "into", "could", "should", "would",
}


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in TOKEN_PATTERN.findall(text) if t.lower() not in STOPWORDS and len(t) > 2]


class KnowledgeRetriever:
    """
    Recuperador de conhecimento baseado em keyword scoring TF-IDF-like.

    Usage:
        kr = KnowledgeRetriever()
        kr.load_knowledge_base()
        exemplos = kr.retrieve("Supabase table users exposed with INSERT permission", top_k=3)
        for ex in exemplos:
            print(ex["title"])
    """

    def __init__(self, kb_dir: str = None):
        self.kb_dir = kb_dir or os.path.join(os.path.dirname(__file__), "knowledge")
        self.kb_path = os.path.join(os.path.dirname(kb_dir or __file__), "reports_knowledge_base.json")
        self.index: List[Dict] = []
        self.doc_freq: Counter = Counter()
        self.total_docs: int = 0

    def load_knowledge_base(self):
        self.index = []
        self.doc_freq = Counter()
        docs = []

        # 1. Carrega reports_knowledge_base.json
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path) as f:
                    data = json.load(f)
                    for finding in data.get("real_findings", []):
                        doc = {
                            "source": "json",
                            "title": finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "cwe": finding.get("cwe", ""),
                            "description": finding.get("description", ""),
                            "attack_vector": finding.get("attack_vector", ""),
                            "remediation": finding.get("remediation", ""),
                            "cvss": finding.get("cvss", ""),
                            "source_name": finding.get("source", ""),
                            "tags": self._extract_tags(finding),
                        }
                        docs.append(doc)
            except Exception as e:
                print(f"[KR] Erro carregando JSON KB: {e}")

        # 2. Carrega arquivos .md do diretorio knowledge/
        if os.path.isdir(self.kb_dir):
            for fname in os.listdir(self.kb_dir):
                if fname.endswith(".md"):
                    fpath = os.path.join(self.kb_dir, fname)
                    try:
                        with open(fpath) as f:
                            content = f.read()
                        head = content.split("\n")[0] if content else fname
                        # Extrai tags da linha de metadados
                        meta_tags = self._parse_meta_tags(content)
                        docs.append({
                            "source": "markdown",
                            "title": head.strip("# \n"),
                            "severity": meta_tags.get("severidade", "Info"),
                            "cwe": meta_tags.get("cwe", "N/A"),
                            "description": content[:800],
                            "attack_vector": "",
                            "remediation": "",
                            "cvss": "",
                            "source_name": fname,
                            "tags": self._extract_tags({"title": head, "description": content, "tags": meta_tags}),
                        })
                    except Exception as e:
                        print(f"[KR] Erro carregando MD {fname}: {e}")

        self.index = docs
        self.total_docs = len(docs)

        # 3. Calcula document frequency para IDF
        for doc in docs:
            tokens = set(doc["tags"])
            for t in tokens:
                self.doc_freq[t] += 1

    def _parse_meta_tags(self, content: str) -> dict:
        meta = {}
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("**CAMADA="):
                parts = line.strip("**").split("|")
                for p in parts:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        meta[k.strip().lower()] = v.strip()
        return meta

    def _extract_tags(self, finding: dict) -> List[str]:
        text = " ".join([
            finding.get("title", ""),
            finding.get("description", ""),
            finding.get("attack_vector", ""),
            finding.get("cwe", ""),
            " ".join(finding.get("tags", {}).values()) if isinstance(finding.get("tags"), dict) else "",
        ])
        return _tokenize(text)

    def retrieve(self, query: str, top_k: int = 4, plugin_source: str = "") -> List[Dict]:
        if not self.index:
            self.load_knowledge_base()
        if not self.index:
            return []

        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        idf = {}
        for t in query_tokens:
            df = self.doc_freq.get(t, 1)
            idf[t] = math.log((self.total_docs + 1) / (df + 1)) + 1

        scored = []
        for doc in self.index:
            score = 0.0
            doc_tokens = set(doc["tags"])
            for t in query_tokens:
                if t in doc_tokens:
                    score += idf.get(t, 1.0)

            # Bonus se o plugin_source corresponde a categoria
            if plugin_source:
                ps_lower = plugin_source.lower()
                if ps_lower in doc["title"].lower() or ps_lower in doc["description"].lower():
                    score *= 1.5

            if score > 0:
                scored.append((score, doc))

        scored.sort(key=lambda x: -x[0])
        return [doc for _, doc in scored[:top_k]]

    def format_for_prompt(self, query: str, top_k: int = 3, plugin_source: str = "") -> str:
        examples = self.retrieve(query, top_k, plugin_source)
        if not examples:
            return ""
        parts = []
        for i, ex in enumerate(examples):
            parts.append(f"--- EXEMPLO RELEVANTE #{i+1} ({ex['source_name']}) ---")
            parts.append(f"Titulo: {ex['title']}")
            parts.append(f"Severidade: {ex['severity']} | CWE: {ex['cwe']}")
            parts.append(f"Descricao: {ex['description'][:300]}")
            if ex.get("attack_vector"):
                parts.append(f"Vetor: {ex['attack_vector'][:200]}")
            if ex.get("remediation"):
                parts.append(f"Remediacao: {ex['remediation'][:200]}")
            parts.append("")
        return "\n".join(parts)


# Singleton
_retriever = None

def get_retriever() -> KnowledgeRetriever:
    global _retriever
    if _retriever is None:
        _retriever = KnowledgeRetriever()
        _retriever.load_knowledge_base()
    return _retriever
