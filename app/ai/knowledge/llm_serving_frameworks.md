# LLM Serving Frameworks — Análise para Jaizz Noir

## 1. FastChat (lm-sys)
- **Repo**: github.com/lm-sys/fastchat (18k+ ★)
- **Propósito**: Plataforma open-source para treinar, servir e avaliar chatbots LLM (Vicuna, Chatbot Arena).
- **Diferenciais**: Web UI própria, controller + worker distribuído, API OpenAI-compatível.
- **Relevância**: Servir nosso próprio modelo local para PentestAI sem depender de Groq.
- **Status**: Maduro, mas SGLang é mais performático para produção.

## 2. SGLang (sgl-project)
- **Repo**: github.com/sgl-project/sglang (14k+ ★)
- **Propósito**: Serving de alta performance para LLMs e modelos multimodais.
- **Diferenciais**: RadixAttention (prefix caching), disaggregação prefill/decode, speculative decoding, parallelism multi-GPU (tensor/pipeline/expert/data), 400k+ GPUs em produção.
- **Relevância**: ALTA — se quisermos rodar LLM local para análise de findings sem depender de Groq.
- **Status**: Muito ativo (54 releases, última v0.5.14 Jun 2026), 460 contribuidores.

## 3. SpecForge (sgl-project)
- **Repo**: github.com/sgl-project/SpecForge
- **Propósito**: Framework para treinar modelos de speculative decoding, portáveis para SGLang.
- **Diferenciais**: Treinamento online/offline/FSDP/tensor-parallel, SpecBundle (modelos pré-treinados), até 4x speedup.
- **Relevância**: Se adotarmos SGLang, SpecForge acelera resposta do LLM em 2-4x via speculative decoding.
- **Status**: Projeto flagship do LMSYS, v0.2 lançado Dec 2025.

## 4. RouteLLM (lm-sys)
- **Repo**: github.com/lm-sys/routellm (4k+ ★)
- **Propósito**: Framework para rotear queries entre modelos LLM (caro/forte vs barato/fraco).
- **Diferenciais**: 4 routers pré-treinados (mf, sw_ranking, bert, causal_llm), drop-in replacement OpenAI, reduz custos em até 85% mantendo 95% da qualidade GPT-4.
- **Relevância**: Se tivermos múltiplos modelos (ex: Groq + local), RouteLLM decide qual usar por query — economia de tokens/custo.
- **Status**: Maduro, paper publicado, routers generalizam para diferentes pares de modelo.

## 5. S-LoRA (s-lora)
- **Repo**: github.com/s-lora/s-lora
- **Propósito**: Servir milhares de adapters LoRA concorrentemente a partir de um base model.
- **Diferenciais**: Unified Paging (KV cache + adapter weights), tensor parallelism especializado, CUDA kernels otimizados, 4x throughput vs vLLM+PEFT.
- **Relevância**: Se tivermos múltiplos fine-tunes especializados (ex: um para XSS, um para SQLi, um para OSINT), S-LoRA serve todos do mesmo base model.
- **Status**: Paper publicado no MLSys 2024. Código disponível, mas menos ativo que SGLang.

## 6. LookaheadDecoding (hao-ai-lab)
- **Repo**: github.com/hao-ai-lab/LookaheadDecoding
- **Propósito**: Decodificação paralela sem draft model — acelera LLM inference.
- **Diferenciais**: Não precisa de draft model nem data store. Reduz passos de decodificação linearmente com log(FLOPs). Suporte FlashAttention.
- **Relevância**: Técnica complementar — pode ser usada junto com SGLang para aceleração adicional.
- **Status**: ICML 2024. Suporte limitado (só LLaMA). Menos ativo que SpecForge.

## Relevância para o Pipeline Jaizz Noir

### Agora (com Groq externo)
- **RouteLLM** (mais relevante): Roteia entre Groq (caro/rápido) e modelos locais (grátis/lento) se tivermos fallback local.
- **LookaheadDecoding/SpecForge**: Não aplicável (não controlamos o servidor Groq).

### Futuro (servidor local próprio)
- **SGLang**: Escolha #1 para servir LLM local com alta performance e suporte a OpenAI API.
- **SpecForge**: Acelera SGLang via speculative decoding (2-4x).
- **S-LoRA**: Se precisarmos de múltiplos especialistas (adapter por tipo de ataque).
- **FastChat**: Alternativa mais simples se não precisar de máxima performance.

### Recomendação
Se migrarmos de Groq para servidor próprio:
1. SGLang como backend principal
2. SpecForge para aceleração via speculative decoding
3. RouteLLM para gerenciar múltiplas fontes (ex: local + Groq como fallback)
4. S-LoRA se surgir necessidade de múltiplos especialistas LoRA
