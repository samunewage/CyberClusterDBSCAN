# Diario de Uso de Inteligencia Artificial (Diario de IA)

**Projeto:** CyberCluster - Agrupamento e Deteccao de Anomalias em Conexoes de Rede (CICIDS2017)  
**Instituicao:** Faculdades Integradas de Bauru (FIB)  
**Disciplina:** Inteligencia Artificial II  
**Autores:**
- Samuel Esperanca Vieira Panobianco
- Bryan Williams Souto Silva
- Lucas Miguel Cardoso de Almeida
- Renan Denadai de Paul  

---

## 1. Visao Geral e Politica de Uso de IA

O presente documento atesta o registro metodico e auditavel do uso de ferramentas de Inteligencia Artificial no ciclo de desenvolvimento do projeto CyberCluster. A IA atuou como ferramenta de aceleracao de escrita de boilerplate, geracao de codigo modular e documentacao tecnica sob a supervisao e validacao conceitual continua dos autores humanos.

Todas as decisoes referentes a formulacao matematica, complexidade assintotica dos algoritmos, tratamento de matrizes esparsas, prevencao de vazamento de dados e selecao de hiperparametros foram estritamente validadas pela equipe tecnica.

---

## 2. Registro Estruturado de Sessoes

### Sessao 01 - Estruturacao do Pipeline de Dados e Tratamento Numerico
- **Data:** 22/10/2026
- **Ferramenta Utilizada:** Antigravity IDE / Assistente
- **Versao do Modelo:** Gemini 3.8 Flash (Medium)
- **Prompt Aplicado:**
  > "Estruture e implemente todo o codigo do projeto CyberCluster no diretorio atual de trabalho. O projeto aplica o algoritmo DBSCAN em conexoes de rede do CICIDS2017 com baseline em K-Means. Documente cada script no topo explicando objetivo, entradas, saidas e fluxo de execucao, alem de comentarios detalhando a razao tecnica de cada etapa."
- **Aproveitamento e Adaptacoes:**
  - *Aproveitamento:* Estruturacao em blocos tematicos (Bloco 1 ao Bloco 6), saneamento numerico com substituicao de np.inf por NaN e descarte seguro para manter a integridade da FPU.
  - *Adaptacao Tecnica Humana:* Implementacao de um gerador estocastico representativo como contingencia operacional caso o dataset de 50GB nao esteja fisicamente presente em data/raw/, permitindo testes imediatos e reprodutibilidade de ponta a ponta.

---

### Sessao 02 - Estimativa Analitica de Epsilon, K-Distance Graph e Cenarios
- **Data:** 22/10/2026
- **Ferramenta Utilizada:** Antigravity IDE / Assistente
- **Versao do Modelo:** Gemini 3.8 Flash (Medium)
- **Prompt Aplicado:**
  > "Implementar no pipeline um metodo para plotar e salvar a curva do k-distance graph com k=2*dimensoes para estimativa do joelho de eps. Adicionar no app.py a opcao de alternar entre o dia de DDoS e PortScan. Salvar metricas e matrizes de contingencia em arquivos .json em uma pasta reports/. Nao utilize emojis nem decoracoes informais; mantenha comentarios estritamente tecnicos com complexidade O(N) e fundamentacao estatistica."
- **Aproveitamento e Adaptacoes:**
  - *Aproveitamento:* Codificacao da rotina estimar_joelho_k_distance utilizando NearestNeighbors(n_neighbors=k, n_jobs=-1), computacao da distancia vetorial ortogonal a reta secante unitaria para localizacao automatica da deflexao maxima, e plotagem do grafico em reports/figures/k_distance_graph.png.
  - *Adaptacao Tecnica Humana:* Extensao da classe de geracao sintetica para modelar individualmente os perfis comportamentais de DDoS (altas taxas de bytes e pacotes com ACK constante) e PortScan (tempos inferiores a 10 ms, tamanho de pacote de 40 bytes e flags SYN dominantes), garantindo fidelidade com os CSVs Friday-WorkingHours do CICIDS2017.

---

## 3. Evidencias de Validacao Tecnica Humana

### 3.1. Tratamento Rigoroso de Divisoes por Zero
No calculo de vazao temporal efetuado pelo extrator CICFlowMeter:
$$\text{Flow Bytes/s} = \frac{\text{Total Length of Flow}}{\text{Flow Duration}}$$
Quando a duracao e nula ou inferior a granularidade do clock da interface de rede, ocorre divisao por zero na FPU, gerando infinitos e NaN. A equipe validou a eliminacao desses registros antes do ajuste matricial, assegurando que o espaco euclidiano permanecesse fechado e livre de singularidades.

### 3.2. Prevencao de Data Leakage Topologico
Atributos como 'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port' e 'Timestamp' identificam maquinas fisicas da bancada de teste. Caso mantidos, o modelo aprenderia apenas os IPs das maquinas de teste, tornando-se ineficaz para aplicacao em redes corporativas externas. A equipe homologou o expurgo previo dessas variaveis e o isolamento cego do rotulo 'Label'.

### 3.3. Deteccao Vetorial de Cotovelo na Curva de k-Distancias
A determinacao de epsilon por inspecao visual humana e subjetiva. A equipe validou o algoritmo analitico de maxima distancia perpendicular a reta secante:
$$\text{distancia}_i = x_i^{\text{norm}} - y_i^{\text{norm}}$$
Onde $x_i^{\text{norm}} = \frac{i}{N-1}$ e $y_i^{\text{norm}} = \frac{d_i - d_0}{d_{N-1} - d_0}$.
O indice $i^*$ que maximiza essa diferenca corresponde a maior curvatura da funcao de distribuicao acumulada de distancias locais, fornecendo a estimativa de epsilon com embasamento matematico rigoroso.

---

## 4. Declaracao de Integridade Academica

Os autores confirmam que toda a logica de programacao, analise de complexidade computacional e interpretacao dos resultados tecnicos foram devidamente validadas, auditadas e compreendidas por todos os integrantes da equipe.
