# CyberCluster: Deteccao de Anomalias e Agrupamento de Fluxos de Rede (CICIDS2017)

---

## Autores e Vinculo Institucional

- **Samuel Esperanca Vieira Panobianco**
- **Bryan Williams Souto Silva**
- **Lucas Miguel Cardoso de Almeida**
- **Renan Denadai de Paul**

**Instituicao de Ensino:** Faculdades Integradas de Bauru (FIB)  
**Disciplina:** Inteligencia Artificial II / Mineração de Dados  

---

## 1. Problema e Contexto

Em infraestruturas corporativas modernas, a triagem manual de incidentes de seguranca e a criacao de assinaturas estaticas (sistemas IDS como Snort e Suricata) mostram-se ineficazes frente a ataques zero-day, varreduras stealth (PortScan) e variacoes dinamicas de negacao de servico (DDoS).

O projeto **CyberCluster** aborda o desafio da **triagem autonoma de tráfego anomalo** e a descoberta de padroes de ataque nao rotulados por meio de algoritmos de **Aprendizado de Maquina Nao Supervisionado**. O nucleo metodologico fundamenta-se na aplicacao do algoritmo **DBSCAN** (*Density-Based Spatial Clustering of Applications with Noise*) para segregar tráfego legitimo de anomalias com base exclusivamente na densidade hiperdimensional de conexoes, utilizando o algoritmo **K-Means** como baseline comparativo.

---

## 2. Dataset e Fonte dos Dados

O projeto utiliza o benchmark **CICIDS2017** (*Canadian Institute for Cybersecurity / University of New Brunswick*). O conjunto de dados contem mais de 80 atributos comportamentais extraidos pelo software *CICFlowMeter*, contemplando fluxos benignos e ataques contemporaneos.

### Cenarios Suportados:
1. **Trafego Misto (Normal + DDoS + PortScan):** Avaliacao simultanea da coexistencia de multiplas classes de ataque com tráfego legitimo na mesma projecao espacial.
2. **DDoS (Friday Afternoon):** Tráfego volumetrico massivo com alta cadencia de pacotes e bytes por segundo.
3. **PortScan (Friday Morning):** Sondagens atipicas de baixa duracao (< 10 ms), com pacotes reduzidos e predominancia de flags SYN.
4. **Modo de Simulacao Continua (Streaming):** Execucao interativa em loop temporal na interface Streamlit, simulando operacao de SOC com atualizacao automatica de projecoes 2D, metricas de anomalia e matrizes de contingencia por ciclo.

### Instrucoes para Posicionamento dos Dados:
1. Obtenha os arquivos CSV no repositorio oficial da University of New Brunswick:  
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Posicione os arquivos descompactados no diretorio local `data/raw/`:
   - `data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
   - `data/raw/Friday-WorkingHours-Morning-PortScan.pcap_ISCX.csv`
3. Na ausencia fisica dos arquivos brutos (arquivos de dezenas de gigabytes), o pipeline ativa automaticamente um gerador sintetico calibrado com as mesmas dimensoes e distribuicoes estatisticas do CICIDS2017, viabilizando a execucao imediata para testes e demonstracao.

---

## 3. Tecnologias Utilizadas

- **Linguagem Principal:** Python (3.10+)
- **Processamento Matricial e Analise de Dados:** Pandas (>=2.0.0), NumPy (>=1.24.0)
- **Modelagem Nao Supervisionada e Metricas:** Scikit-Learn (>=1.3.0)
  - *DBSCAN, KMeans, NearestNeighbors, StandardScaler, VarianceThreshold, PCA*
  - *Silhouette Score, Adjusted Rand Index (ARI), Davies-Bouldin Index*
- **Visualizacao Espacial e Graficos:** Plotly (>=5.15.0), Matplotlib (>=3.7.0)
- **Interface Analitica Interativa:** Streamlit (>=1.28.0)

---

## 4. Instrucoes de Execucao

### 4.1. Criacao e Ativacao do Ambiente Virtual
No Windows (PowerShell):
```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
```

No Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4.2. Instalacao das Dependencias
```bash
py -m pip install -r requirements.txt
```

### 4.3. Execucao do Pipeline Analitico
Para executar o pipeline com estimativa de joelho de epsilon via k-distance graph, ajuste de baseline K-Means, agrupamento DBSCAN e exportacao de relatorios JSON:

Cenario DDoS (Padrao):
```bash
py src/pipeline.py --cenario ddos --amostras 10000
```

Cenario PortScan:
```bash
py src/pipeline.py --cenario portscan --amostras 10000
```

*Parametros Adicionais:*
- `--amostras`: Quantidade de conexoes subamostradas (padrao: 10000).
- `--eps`: Valor explicito de epsilon (se omitido, o pipeline utiliza a estimativa analitica do joelho).
- `--min_samples`: Cardinalidade minima de vizinhos para formacao de nucleo denso (padrao: 15).

### 4.4. Inicializacao da Interface Interativa (Streamlit)
Para iniciar a estacao de trabalho interativa no navegador:
```bash
py -m streamlit run app/app.py
```
A aplicacao sera carregada no endereco padrao: `http://localhost:8501`.

---

## 5. Estimativa Analitica do Epsilon (k-distance graph)

Em espacos multidimensionais contínuos, a definicao arbitraria do raio de vizinhanca $\epsilon$ compromete a qualidade da densidade local. O pipeline implementa a heuristica de Ester et al. (1996) e Schubert et al. (2017), dimensionando $k = 2 \times d$ (onde $d$ e a quantidade de atributos informativos apos a selecao de variancia zero).

O algoritmo computa as distancias ao $k$-esimo vizinho mais proximo para cada ponto via `NearestNeighbors`, ordena o vetor de forma ascendente e identifica o ponto de cotovelo (*elbow point*) por meio do metodo da distancia perpendicular maxima a reta secante normalizada no espaco unitario $[0, 1] \times [0, 1]$. O grafico tecnico gerado e automaticamente salvo em:
`reports/figures/k_distance_graph.png`.

---

## 6. Resultados Preliminares e Comparativo Tecnico

Resultados consolidados em amostragem estratificada de 10.000 conexoes do cenario DDoS:

| Metrica Avaliada | Baseline: K-Means (k=3) | DBSCAN (Epsilon Analitico = 2.45, Min_Samples = 15) |
| :--- | :---: | :---: |
| **Silhouette Score (Nucleos Densos)** | 0.3541 | **0.6912** |
| **Adjusted Rand Index (ARI)** | 0.2815 | **0.6430** |
| **Davies-Bouldin Index** | 1.4820 | **0.7810** *(menor indica maior separacao)* |
| **Taxa de Conexoes em Ruido** | 0.00% *(forca inclusao indevida)* | **8.12%** *(isolamento nativo no rotulo -1)* |
| **Topologia dos Clusters** | Estritamente hiper-esferica | Geometria livre baseada em densidade local |

### Analise dos Resultados:
1. **Isolamento de Anomalias:** O K-Means e incapaz de segregar pontos isolados, atribuindo conexoes anomalas ao centroide com menor distancia euclidiana, contaminando os vetores medios de classes normais. O DBSCAN direciona essas conexoes diretamente ao rotulo -1 (Ruido).
2. **Coesao Estrutural:** O indice Davies-Bouldin obtido pelo DBSCAN nos nucleos densos foi substancialmente inferior ao K-Means, confirmando que os grupos densos apresentam maior compacidade interna e maior distancia inter-cluster.

---

## 7. Estrutura de Diretorios do Projeto

```text
CyberCluster/
├── .gitignore                      # Regras de exclusao para dados brutos, venv e caches
├── requirements.txt                # Dependencias do projeto
├── README.md                       # Documentacao tecnica institucional
├── data/
│   ├── raw/                        # Diretorio para CSVs brutos do CICIDS2017 (.gitkeep)
│   └── processed/                  # Amostras pre-processadas com predicoes dos modelos
├── src/
│   └── pipeline.py                 # Pipeline analitico completo e modular (Blocos 1 a 8)
├── app/
│   └── app.py                      # Interface analitica em Streamlit com projecao PCA e k-distancia
├── reports/
│   ├── metrics_summary.json        # Resumo de metricas de coesao e concordancia externa
│   ├── contingency_matrix.json     # Tabela de contingencia serializada
│   └── figures/
│       └── k_distance_graph.png    # Grafico da curva de k-distancia com marcacao de joelho
└── docs/
    └── Diario_de_IA.md             # Registro auditavel de sessoes e validacoes tecnicas
```
