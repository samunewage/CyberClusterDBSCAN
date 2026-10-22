# Diário de Uso de Ferramentas de IA

**Projeto:** CyberCluster — Análise de Tráfego de Rede com DBSCAN  
**Instituição:** Faculdades Integradas de Bauru (FIB)  
**Disciplina:** Inteligência Artificial II  
**Integrantes:** Samuel Esperança Vieira Panobianco, Bryan Williams Souto Silva, Lucas Miguel Cardoso de Almeida, Renan Denadai de Paul  

---

## 1. Visão Geral

Este documento registra as consultas pontuais realizadas com ferramentas de Inteligência Artificial para auxílio no levantamento de referências, dúvidas de sintaxe em bibliotecas Python (Pandas e Scikit-Learn) e organização da interface gráfica do protótipo. Todas as implementações, decisões de pré-processamento e análises de resultados foram desenvolvidas e validadas diretamente pela equipe.

---

## 2. Registro de Consultas

### Sessão 1 — Pesquisa Bibliográfica e Validação do Problema
- **Data:** 21/10/2026
- **Ferramenta:** ChatGPT
- **Objetivo da Consulta:** Levantamento de artigos de referência sobre aplicação de DBSCAN em tráfego de rede e artigos críticos sobre inconsistências de fluxo no dataset CICIDS2017.
- **Resultado / Uso:** A ferramenta indicou a leitura do artigo de Schubert et al. (2017) sobre diretrizes de uso do DBSCAN e de Engelen et al. (2021) sobre problemas no CICIDS2017. A equipe consultou os textos e os utilizou na fundamentação da metodologia.

---

### Sessão 2 — Tratamento de Valores Especiais no Pandas
- **Data:** 22/10/2026
- **Ferramenta:** Gemini
- **Objetivo da Consulta:** Dúvida de sintaxe sobre como substituir eficientemente valores infinitos (`inf` e `-inf`) gerados por divisão por zero nas colunas de taxa do dataset antes de aplicar a padronização.
- **Resultado / Uso:** Foi adotado o encadeamento de `df.replace([np.inf, -np.inf], np.nan)` com `dropna()`, garantindo que apenas registros numéricos válidos entrassem no padronizador.

---

### Sessão 3 — Cálculo Vetorial do Joelho na Curva de k-Distâncias
- **Data:** 23/10/2026
- **Ferramenta:** Gemini
- **Objetivo da Consulta:** Esclarecimento matemático sobre o método da distância perpendicular à reta secante para identificação analítica do ponto de inflexão (cotovelo) na curva de k-distâncias.
- **Resultado / Uso:** A fórmula vetorial normalizada foi compreendida pelo grupo e implementada no script `pipeline.py` para sugerir o parâmetro `eps` inicial de forma não subjetiva.

---

### Sessão 4 — Organização dos Componentes no Streamlit
- **Data:** 24/10/2026
- **Ferramenta:** ChatGPT / Gemini
- **Objetivo da Consulta:** Dúvida sobre a melhor forma de organizar múltiplas visualizações (projeção 2D, tabelas de contingência e gráficos de métricas) em abas sem sobrecarregar a interface.
- **Resultado / Uso:** Foi utilizada a estrutura de `st.tabs()` e controles na barra lateral (`st.sidebar`) no arquivo `app.py`, facilitando a navegação durante a apresentação.

---

## 3. Validações Realizadas pela Equipe

- **Prevenção de Vazamento de Dados:** Verificação manual para garantir que a coluna de rótulos (`Label`) não fosse utilizada no treinamento ou padronização, ficando restrita à conferência final das métricas.
- **Remoção de Identificadores:** Decisão própria da equipe de descartar colunas de IP, porta e timestamp, forçando os modelos a agruparem conexões exclusivamente pelo comportamento volumétrico e temporal.
- **Conferência das Métricas:** Todos os valores de Silhueta, ARI e proporção de ruído gerados pelo pipeline foram inspecionados diretamente pelos integrantes.
