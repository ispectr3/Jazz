# OWASP Top 10 for Large Language Model Applications (v1.1)

> **CAMADA=IA | DOMINIO=LLM, ML | SEGURANCA=OWASP, LLM Security | PILARES=8/8**

## LLM01: Prompt Injection
Manipulating LLMs via crafted inputs can lead to unauthorized access, data breaches, and compromised decision-making.
- **Ferramentas:** Garak, PyRIT, PromptInjector, LLM Guard, Rebuff, HarmBench

## LLM02: Insecure Output Handling
Neglecting to validate LLM outputs may lead to downstream security exploits, including code execution.
- **Ferramentas:** LLM Guard (output scanners)

## LLM03: Training Data Poisoning
Tampered training data can impair LLM models leading to responses that may compromise security.
- **Ferramentas:** HarmBench (adversarial training evaluation)

## LLM04: Model Denial of Service
Overloading LLMs with resource-heavy operations can cause service disruptions.
- **Ferramentas:** LLM Guard (TokenLimit scanner)

## LLM05: Supply Chain Vulnerabilities
Depending upon compromised components, services or datasets undermine system integrity.
- **Ferramentas:** N/A (auditoria de dependencias)

## LLM06: Sensitive Information Disclosure
Failure to protect against disclosure of sensitive information in LLM outputs.
- **Ferramentas:** LLM Guard (Secrets, Anonymize), Garak (data leakage probes)

## LLM07: Insecure Plugin Design
LLM plugins processing untrusted inputs and having insufficient access control.
- **Ferramentas:** PentestAI (scanner de plugins)

## LLM08: Excessive Agency
Granting LLMs unchecked autonomy to take action can lead to unintended consequences.
- **Ferramentas:** PentestAI (avaliacao de permissoes)

## LLM09: Overreliance
Failing to critically assess LLM outputs can lead to compromised decision making.
- **Ferramentas:** PromptBench (avaliacao de acuracia)

## LLM10: Model Theft
Unauthorized access to proprietary large language models risks theft.
- **Ferramentas:** PyRIT (model extraction probes)

## Mapeamento para Ferramentas do Jaizz Noir
| OWASP LLM | Garak | PyRIT | LLM Guard | HarmBench | PromptBench | PentestAI |
|---|---|---|---|---|---|---|
| LLM01 | ✓ | ✓ | ✓ | ✓ |   | ✓ |
| LLM02 |   |   | ✓ |   |   |   |
| LLM03 |   |   |   | ✓ |   |   |
| LLM04 |   |   | ✓ |   |   |   |
| LLM05 |   |   |   |   |   | ✓ |
| LLM06 | ✓ |   | ✓ |   |   |   |
| LLM07 |   |   |   |   |   | ✓ |
| LLM08 |   |   |   |   |   | ✓ |
| LLM09 |   |   |   |   | ✓ |   |
| LLM10 |   | ✓ |   |   |   |   |
