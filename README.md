

---

# CyberCluster: Deteccao de Anomalias e Agrupamento de Fluxos de Rede (CICIDS2017)

---

## Autores e Vinculo Institucional

- **Samuel Esperanca Vieira Panobianco**
- **Bryan Williams Souto Silva**
- **Lucas Miguel Cardoso de Almeida**
- **Renan Denadai de Paul**

**Instituicao de Ensino:** Faculdades Integradas de Bauru (FIB)  
**Curso:** Engenharia de Computacao / Ciencia da Computacao  
**Disciplina:** Inteligencia Artificial II / Mineracao de Dados  

---

## 1. Problema e Contexto

A triagem manual de eventos de seguranca da informacao e a utilizacao de assinaturas deterministicas em sistemas IDS/IPS convencionais apresentam ineficiencia frente a ataques de dia zero (zero-day), varreduras discretas (PortScan) e incidentes volumetricos de negacao de servico (DDoS).

O projeto **CyberCluster** implementa uma abordagem analitica baseada em **Aprendizado de Maquina Nao Supervisionado**. Utiliza-se o algoritmo **DBSCAN** (*Density-Based Spatial Clustering of Applications with Noise*) para realizar a separacao autonoma entre fluxos legitimos e atipicos no espaco euclidiano multidimensional, confrontando seu desempenho contra o modelo baseline **K-Means**.

---

## 2. Pre-Requisitos de Sistema

Antes de iniciar a instalacao, assegure que a estacao de trabalho atenda aos seguintes requisitos minimos de ambiente:

- **Sistema Operacional:** Windows 10/11 (64 bits), Linux (Ubuntu 20.04+ / Debian 11+) ou macOS (12+).
- **Interpretador Python:** Python versao 3.10, 3.11 ou 3.12 instalada e adicionada ao PATH do sistema operacional.
- **Gerenciador de Pacotes:** `pip` atualizado para a versao mais recente.
- **Controle de Versao:** Git instalado localmente (necessario para clonagem via terminal).
- **Recursos de Hardware Recomendados:**
  - Memoria RAM: Minimo de 8 GB (Recomendado: 16 GB para processamento de matrizes de distancia).
  - Espaco em Disco: 2 GB livres para codigo e dependencias (caso utilize os CSVs brutos do CICIDS2017, reserve ao menos 15 GB adicionais).
- **Navegador Web para a Interface (Importante):**
  - Recomenda-se a utilizacao de navegadores com suporte a WebGL habilitado para a renderizacao dos graficos interativos do Plotly: **Mozilla Firefox**, **Microsoft Edge**, **Brave** ou **Safari**.
  - *Observacao Tecnica sobre Google Chrome:* Em determinadas distribuicoes corporativas ou perfis do Google Chrome com aceleracao de hardware restrita por politica de seguranca ou extensoes de bloqueio de script ativas, a renderizacao WebGL de dispersao 2D pode sofrer limitacao de framerate ou travamento de aba. Caso ocorra lentidao, abra a aplicacao preferencialmente no **Mozilla Firefox** ou **Microsoft Edge**.

---

## 3. Obtencao do Codigo-Fonte (Download do Git)

### Opcao A: Clonagem via Terminal Git (Recomendado)
Abra o prompt de comando (PowerShell no Windows ou Bash no Linux/macOS) e execute:

```bash
git clone https://github.com/seu-usuario/CyberCluster.git
cd CyberCluster
```

### Opcao B: Download em Arquivo Compactado (.ZIP)
Caso nao possua o utilitario Git instalado:
1. Na pagina principal do repositorio no GitHub, clique no botao **Code**.
2. Selecione a opcao **Download ZIP**.
3. Descompacte o arquivo no diretorio de sua preferencia.
4. Abra o terminal e navegue ate a pasta descompactada:
```bash
cd caminho/para/CyberCluster-main
```

---

## 4. Estrutura de Diretorios

```text
CyberCluster/
|-- .gitignore                      # Regras de exclusao de dados brutos e ambientes virtuais
|-- requirements.txt                # Dependencias e bibliotecas do ecossistema Python
|-- README.md                       # Documentacao tecnica do projeto
|-- data/
|   |-- raw/                        # Diretorio para recepcao dos CSVs brutos do CICIDS2017
|   `-- processed/                  # Amostras pre-processadas com predicoes dos modelos
|-- src/
|   `-- pipeline.py                 # Pipeline analitico completo (saneamento, modelagem e metricas)
|-- app/
|   `-- app.py                      # Dashboard interativo com Streamlit e simulacao em tempo real
|-- reports/
|   |-- metrics_summary.json        # Relatorio serializado de metricas (Silhueta, ARI, Davies-Bouldin)
|   |-- contingency_matrix.json     # Matriz de contingencia dos clusters frente ao ground truth
|   `-- figures/
|       `-- k_distance_graph.png    # Grafico da curva de k-distancia com marcacao vetorial de joelho
`-- docs/
    `-- Diario_de_IA.md             # Registro auditavel de sessoes e validacoes tecnicas
```

---

## 5. Dataset de Referencia e Contingencia Operacional

O projeto opera sobre o benchmark de ciberseguranca **CICIDS2017** (*Canadian Institute for Cybersecurity / University of New Brunswick*):
- **Cenario DDoS:** `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- **Cenario PortScan:** `Friday-WorkingHours-Morning-PortScan.pcap_ISCX.csv`

### Instrucoes para Inclusao dos Dados Brutos:
1. Faca o download dos arquivos no portal oficial da UNB:  
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Deposite os arquivos descompactados na pasta local `data/raw/`.

> **Mecanismo de Contingencia Integrado:** Caso o usuario execute o codigo sem os arquivos fisicos de varios gigabytes na pasta `data/raw/`, o modulo de ingestao detecta automaticamente a ausencia e ativa um gerador sintetico calibrado estatisticamente com as mesmas 80 dimensoes e distribuicoes do CICIDS2017. Isso permite testar integralmente o pipeline e a interface sem bloqueios de execucao.

---

## 6. Procedimento Passo a Passo de Instalacao e Execucao

### Passo 6.1: Criar e Ativar o Ambiente Virtual Isolado

No Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

*Caso ocorra erro de politica de execucao de scripts no PowerShell, execute previamente:*
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

No Linux / macOS (Bash):
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Passo 6.2: Atualizar o Gerenciador e Instalar Dependencias

Com o ambiente virtual ativado, instale os pacotes definidos no `requirements.txt`:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Passo 6.3: Executar o Pipeline Analitico via Linha de Comando

O script `src/pipeline.py` processa a higienizacao de dados, remove o risco de data leakage, calcula a estimativa de epsilon pelo k-distance graph, ajusta os modelos K-Means e DBSCAN e persiste os relatorios na pasta `reports/`.

Para executar com o cenario padrao (DDoS):
```bash
python src/pipeline.py --cenario ddos --amostras 10000
```

Para executar com o cenario de PortScan:
```bash
python src/pipeline.py --cenario portscan --amostras 10000
```

Para executar com o cenario de Trafego Misto (Normal + DDoS + PortScan):
```bash
python src/pipeline.py --cenario misto --amostras 10000
```

---

### Passo 6.4: Iniciar a Aplicacao Web Interativa (Streamlit)

Para abrir a estacao analitica interativa:
```bash
streamlit run app/app.py
```

Caso o navegador nao abra automaticamente, copie o endereco fornecido no terminal e abra manualmente:
```text
http://localhost:8501
```

*Recomendacao Operacional de Navegacao:*
Para garantir a renderizacao fluida das projecoes espaciais em WebGL (Plotly) e evitar eventuais bloqueios de aceleracao de hardware do Google Chrome, abra a URL `http://localhost:8501` prioritariamente no **Mozilla Firefox** ou no **Microsoft Edge**.

---

## 7. Resultados Tecnicos e Quadro Comparativo

Metricas aferidas em teste amostral estratificado de 10.000 instancias sobre o cenario de DDoS:

| Metrica Avaliada | Baseline: K-Means (k=3) | Modelo DBSCAN (eps=1.12, min_samples=15) |
| :--- | :---: | :---: |
| **Silhouette Score (Nucleos Densos)** | 0.5147 | **0.6418** |
| **Adjusted Rand Index (ARI)** | 0.6899 | **0.6836** |
| **Davies-Bouldin Index** | 0.9618 | **0.4689** *(menor indica maior compacidade)* |
| **Taxa de Conexoes em Ruido** | 0.00% *(forca inclusao indevida)* | **3.25%** *(isolamento nativo no cluster -1)* |
| **Geometria de Decisao** | Esferica rigida (Voronoi) | Topologia livre por densidade local |

### Justificativas Tecnicas das Conclusoes:
1. **Inadequacao do K-Means em Seguranca:** O K-Means assume a priori que os dados sao gaussianos e esfericos. Conexoes maliciosas raras ou sondagens de rede sao compulsoriamente alocadas ao centroide mais proximo, corrompendo os parametros medios de tráfego benigno.
2. **Eficacia do Isolamento DBSCAN:** O DBSCAN identifica organicamente conexoes isoladas e direciona pacotes anomalos ao cluster `-1` (Ruido), fornecendo um mecanismo confiavel para geracao de alertas em centros de operacoes de seguranca (SOC).
