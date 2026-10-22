"""
====================================================================================================
PROJETO CYBERCLUSTER - PIPELINE DE AGRUPAMENTO DE FLUXOS DE REDE (CICIDS2017)
====================================================================================================

MODULO: src/pipeline.py
AUTORES: Samuel Esperanca Vieira Panobianco, Bryan Williams Souto Silva,
         Lucas Miguel Cardoso de Almeida, Renan Denadai de Paul.
INSTITUICAO: Faculdades Integradas de Bauru (FIB)
DISCIPLINA: Inteligencia Artificial II / Mineração de Dados

1. OBJETIVO DO MODULO:
----------------------------------------------------------------------------------------------------
Este modulo implementa o pipeline analitico para processamento, saneamento, reducao de dimensionalidade,
analise de k-distancia para estimativa geometrica de epsilon e modelagem comparativa de agrupamento
de conexoes de rede do benchmark CICIDS2017 (cenarios de DDoS e PortScan).
O objetivo principal e a identificacao autonoma de anomalias e fluxos maliciosos atraves de agrupamento
baseado em densidade (DBSCAN) confrontado com particao esferica centroidal (K-Means).

2. FLUXO DE EXECUCAO PONTA A PONTA:
----------------------------------------------------------------------------------------------------
  [1. Ingestao e Validacao de Dados]
          |  Carregamento do CSV bruto (CICIDS2017 DDoS ou PortScan) ou gerador sintetico de contingencia.
          v
  [2. Saneamento Numerico e Normalizacao de Cabecalhos]
          |  Normalizacao de strings de cabecalho (trim) e tratamento estrito de divisoes por zero
          |  (np.inf, -np.inf, NaN) nas taxas temporais de transferencia (Flow Bytes/s, Flow Packets/s).
          v
  [3. Prevencao de Data Leakage e Selecao de Features]
          |  Expurgo mandatorio de identificadores de topologia (Flow ID, IPs, Portas, Timestamps),
          |  eliminacao de preditores com variancia zero e segregacao estrita do rotulo (Label) para
          |  auditoria cega externa.
          v
  [4. Amostragem Estratificada / Representativa]
          |  Reducao de volume para mitigacao da complexidade assintotica O(N^2) de memoria e tempo
          |  do calculo de vizinhancas e matrizes de distancia euclidiana do DBSCAN.
          v
  [5. Padronizacao Z-Score (StandardScaler)]
          |  Equalizacao dimensional para compatibilizacao de grandezas heterogeneas (bytes vs microsegundos).
          v
  [6. Estimativa Analitica do Epsilon (k-distance graph)]
          |  Calculo da distancia ao k-esimo vizinho mais proximo (k = 2 * dimensoes), ordenacao vetorial,
          |  deteccao analitica do joelho (curvatura maxima ortogonal a secante) e exportacao de grafico.
          v
  [7. Modelagem Baseline (K-Means)]
          |  Ajuste de particionamento com k=3, mensuracao de Silhueta, ARI e Inercia.
          v
  [8. Modelagem Principal (DBSCAN)]
          |  Agrupamento por densidade local, isolamento de ruido (-1) e calculo de Silhueta dos nucleos.
          v
  [9. Exportacao de Artefatos e Relatorios Analiticos]
             Geracao estruturada de relatorios JSON em reports/ (metrics_summary.json e
             contingency_matrix.json) e amostra tratada em data/processed/.

3. FUNDAMENTACAO TEORICA E COMPLEXIDADE:
----------------------------------------------------------------------------------------------------
- Complexidade Assintotica da Matriz de Distancia do DBSCAN:
  A formulacao basica do DBSCAN requer O(N^2) avaliacoes de distancia euclidiana d(p, q) = sqrt(sum((pi - qi)^2)).
  Em espacos de alta dimensionalidade (d > 20), estruturas de indexacao espacial como KD-Trees e Ball-Trees
  degradam para busca linear devido a Maldicao da Dimensionalidade, resultando em O(d * N^2) de tempo e
  alocacao O(N^2) de memoria RAM. A subamostragem representativa estratificada e condicao sine qua non para
  viabilidade computacional.

- Heuristica do k-distance graph (k = 2 * d):
  Conforme estabelecido por Ester et al. (1996) e Schubert et al. (2017), o hiperparametro min_samples
  deve ser proporcional a dimensionalidade do espaco de features (comum: min_samples >= 2 * d) para
  estabilizar o conceito de densidade contra flutuacoes estocasticas. Fixando k = min_samples, a curva
  ordenada da k-distancia exibe um limiar de transicao brusca (joelho/cotovelo). Pontos a esquerda
  pertencem a componentes densos (clusters); pontos a direita apos a curvatura representam ruido ou
  densidade insuficiente.

====================================================================================================
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

import numpy as np
import pandas as pd

# Configuracao de backend headless para matplotlib antes de importar pyplot
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import VarianceThreshold
from sklearn.cluster import KMeans, DBSCAN
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import silhouette_score, adjusted_rand_score, davies_bouldin_score
from sklearn.model_selection import train_test_split


# ==================================================================================================
# BLOCO 1: INGESTAO E SANEAMENTO NUMERICO DE DADOS
# ==================================================================================================

def carregar_dados(
    caminho_csv: str,
    tipo_cenario: str = "ddos",
    permitir_amostra_sintetica: bool = True
) -> pd.DataFrame:
    """
    Realiza a ingestao dos fluxos de rede do benchmark CICIDS2017 com tratamento de cabecalhos e valores criticos.

    Fundamentacao Tecnica:
    1. Normalizacao de Cabecalhos:
       Os arquivos originais gerados pelo software extrator CICFlowMeter contem espacos residuais nos
       nomes dos atributos (ex.: ' Destination Port', ' Flow Duration '). A remocao sistematica
       via strip() previne falhas de indexacao (KeyError) em operacoes subsequentes do pipeline.

    2. Indeterminacoes Numericas (divisoes por zero):
       Atributos que mensuram taxas de transferencia temporal, como 'Flow Bytes/s' e 'Flow Packets/s',
       sao calculados pela relacao (Tamanho do Fluxo / Duracao do Fluxo). Em conexoes com duracao de
       0 microssegundos (comum em varreduras stealth ou sondagens incompletas), a operacao computa
       divisao por zero na FPU, gerando os simbolos IEEE 754 'np.inf', '-np.inf' e 'NaN'.
       Esses valores invalidam a computacao de matrizes de covariancia, normas euclidianas e gradientes,
       sendo compulsoria sua eliminacao ou conversao antes de qualquer transformacao matricial.

    Entradas:
        caminho_csv (str): Caminho para o arquivo CSV de fluxos.
        tipo_cenario (str): Cenário do dataset ('ddos' ou 'portscan').
        permitir_amostra_sintetica (bool): Flag de contingencia para geracao de dados na ausencia do arquivo bruto.

    Saidas:
        pd.DataFrame: DataFrame higienizado, livre de infinitos e com tipagem consistente.
    """
    arquivo = Path(caminho_csv)

    if not arquivo.exists():
        if permitir_amostra_sintetica:
            print(f"[AVISO] Arquivo {caminho_csv} nao localizado no sistema local.")
            print(f"[INFO] Ativando gerador estocastico representativo do perfil: {tipo_cenario.upper()}...")
            return gerar_dataset_sintetico_cicids2017(tipo_cenario=tipo_cenario)
        else:
            raise FileNotFoundError(
                f"O arquivo {caminho_csv} nao foi encontrado. "
                "Posicione o arquivo bruto do CICIDS2017 no diretorio data/raw/."
            )

    print(f"[INFO] Ingestao de dados iniciada: {arquivo.resolve()}")
    df = pd.read_csv(arquivo, low_memory=False)

    # Normalizacao sistematica dos nomes de colunas
    colunas_originais = df.columns.tolist()
    df.columns = df.columns.str.strip()
    colunas_ajustadas = sum(1 for o, l in zip(colunas_originais, df.columns) if o != l)
    print(f"[INFO] Sanitizacao de cabecalhos: {colunas_ajustadas} atributos continham caracteres espaciais residuais.")

    # Saneamento numerico estrito contra divisoes por zero
    linhas_iniciais = len(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    linhas_finais = len(df)
    descartes = linhas_iniciais - linhas_finais

    print(
        f"[INFO] Saneamento numerico concluido: {descartes} conexoes foram expurgadas por divisao por zero "
        f"ou nulidade ({linhas_finais} conexoes remanescentes)."
    )

    return df


def gerar_dataset_sintetico_cicids2017(
    n_samples: int = 15000,
    tipo_cenario: str = "ddos",
    random_state: int = 42
) -> pd.DataFrame:
    """
    Gera um dataset sintetico com distribuicoes estatisticas calibradas conforme o benchmark CICIDS2017.
    Suporta cenarios especializados de DDoS (Friday Afternoon) e PortScan (Friday Morning).

    Justificativa das Distribuicoes por Classe:
    - BENIGN: Distribuicao exponencial para tempos de fluxo, variabilidade estocastica de pacotes,
      predominancia de flags ACK estabelecidas.
    - DDoS / DoS Hulk: Altissimo volume de pacotes e bytes por unidade de tempo, duracao restrita a media,
      uniformidade geometrica de pacotes frontais de ataque.
    - PortScan: Fluxos de duracao minima (< 10 ms), com 1 ou 2 pacotes por conexao, bytes reduzidos (apenas
      cabecalho TCP), alta presenca de flag SYN sem flag ACK correspondente (tentativa de varredura).
    """
    np.random.seed(random_state)
    n_benign = int(n_samples * 0.70)
    n_ataque = n_samples - n_benign

    # 1. Tráfego Legítimo (BENIGN)
    duracao_benign = np.random.exponential(scale=60000.0, size=n_benign) + 150.0
    fwd_pkts_benign = np.random.poisson(lam=9, size=n_benign) + 1
    bwd_pkts_benign = np.random.poisson(lam=11, size=n_benign) + 1
    bytes_s_benign = (fwd_pkts_benign * 160.0 + bwd_pkts_benign * 850.0) / (duracao_benign / 1000.0)
    pkts_s_benign = (fwd_pkts_benign + bwd_pkts_benign) / (duracao_benign / 1000.0)

    df_benign = pd.DataFrame({
        'Flow Duration': duracao_benign,
        'Total Fwd Packets': fwd_pkts_benign,
        'Total Backward Packets': bwd_pkts_benign,
        'Total Length of Fwd Packets': fwd_pkts_benign * 160.0,
        'Total Length of Bwd Packets': bwd_pkts_benign * 850.0,
        'Flow Bytes/s': bytes_s_benign,
        'Flow Packets/s': pkts_s_benign,
        'Flow IAT Mean': duracao_benign / (fwd_pkts_benign + 1.0),
        'Fwd Packet Length Max': 1460.0,
        'Fwd Packet Length Min': 40.0,
        'Packet Length Mean': 480.0 + np.random.normal(0, 40, n_benign),
        'ACK Flag Count': np.random.binomial(1, 0.92, n_benign),
        'SYN Flag Count': np.random.binomial(1, 0.08, n_benign),
        'Label': 'BENIGN'
    })

    if tipo_cenario.lower() == "misto":
        # 2. Perfil Misto: Coexistencia simultanea de BENIGN, DDoS e PortScan
        n_benign = int(n_samples * 0.60)
        n_ddos = int(n_samples * 0.25)
        n_scan = n_samples - n_benign - n_ddos

        duracao_benign = np.random.exponential(scale=60000.0, size=n_benign) + 150.0
        fwd_pkts_benign = np.random.poisson(lam=9, size=n_benign) + 1
        bwd_pkts_benign = np.random.poisson(lam=11, size=n_benign) + 1
        bytes_s_benign = (fwd_pkts_benign * 160.0 + bwd_pkts_benign * 850.0) / (duracao_benign / 1000.0)
        pkts_s_benign = (fwd_pkts_benign + bwd_pkts_benign) / (duracao_benign / 1000.0)

        df_benign = pd.DataFrame({
            'Flow Duration': duracao_benign,
            'Total Fwd Packets': fwd_pkts_benign,
            'Total Backward Packets': bwd_pkts_benign,
            'Total Length of Fwd Packets': fwd_pkts_benign * 160.0,
            'Total Length of Bwd Packets': bwd_pkts_benign * 850.0,
            'Flow Bytes/s': bytes_s_benign,
            'Flow Packets/s': pkts_s_benign,
            'Flow IAT Mean': duracao_benign / (fwd_pkts_benign + 1.0),
            'Fwd Packet Length Max': 1460.0,
            'Fwd Packet Length Min': 40.0,
            'Packet Length Mean': 480.0 + np.random.normal(0, 40, n_benign),
            'ACK Flag Count': np.random.binomial(1, 0.92, n_benign),
            'SYN Flag Count': np.random.binomial(1, 0.08, n_benign),
            'Label': 'BENIGN'
        })

        duracao_ddos = np.random.normal(loc=1500.0, scale=250.0, size=n_ddos)
        duracao_ddos = np.clip(duracao_ddos, 80.0, None)
        fwd_pkts_ddos = np.random.poisson(lam=75, size=n_ddos) + 25
        bwd_pkts_ddos = np.random.poisson(lam=3, size=n_ddos)
        bytes_s_ddos = (fwd_pkts_ddos * 1440.0) / (duracao_ddos / 1000.0)
        pkts_s_ddos = (fwd_pkts_ddos + bwd_pkts_ddos) / (duracao_ddos / 1000.0)

        df_ddos = pd.DataFrame({
            'Flow Duration': duracao_ddos,
            'Total Fwd Packets': fwd_pkts_ddos,
            'Total Backward Packets': bwd_pkts_ddos,
            'Total Length of Fwd Packets': fwd_pkts_ddos * 1440.0,
            'Total Length of Bwd Packets': bwd_pkts_ddos * 50.0,
            'Flow Bytes/s': bytes_s_ddos,
            'Flow Packets/s': pkts_s_ddos,
            'Flow IAT Mean': duracao_ddos / (fwd_pkts_ddos + 1.0),
            'Fwd Packet Length Max': 1460.0,
            'Fwd Packet Length Min': 450.0,
            'Packet Length Mean': 1250.0 + np.random.normal(0, 25, n_ddos),
            'ACK Flag Count': np.random.binomial(1, 0.96, n_ddos),
            'SYN Flag Count': np.random.binomial(1, 0.04, n_ddos),
            'Label': 'DDoS'
        })

        duracao_scan = np.random.uniform(low=1.0, high=30.0, size=n_scan)
        fwd_pkts_scan = np.random.choice([1, 2], size=n_scan, p=[0.85, 0.15])
        bwd_pkts_scan = np.random.choice([0, 1], size=n_scan, p=[0.80, 0.20])
        bytes_s_scan = (fwd_pkts_scan * 40.0) / (duracao_scan / 1000.0)
        pkts_s_scan = (fwd_pkts_scan + bwd_pkts_scan) / (duracao_scan / 1000.0)

        df_scan = pd.DataFrame({
            'Flow Duration': duracao_scan,
            'Total Fwd Packets': fwd_pkts_scan,
            'Total Backward Packets': bwd_pkts_scan,
            'Total Length of Fwd Packets': fwd_pkts_scan * 40.0,
            'Total Length of Bwd Packets': bwd_pkts_scan * 40.0,
            'Flow Bytes/s': bytes_s_scan,
            'Flow Packets/s': pkts_s_scan,
            'Flow IAT Mean': duracao_scan,
            'Fwd Packet Length Max': 40.0,
            'Fwd Packet Length Min': 40.0,
            'Packet Length Mean': 40.0,
            'ACK Flag Count': np.random.binomial(1, 0.03, n_scan),
            'SYN Flag Count': np.random.binomial(1, 0.97, n_scan),
            'Label': 'PortScan'
        })

        df_consolidado = pd.concat([df_benign, df_ddos, df_scan], ignore_index=True)
    elif tipo_cenario.lower() == "portscan":
        # 2. Perfil PortScan (Sondagens stealth e varreduras de porta)
        duracao_scan = np.random.uniform(low=1.0, high=30.0, size=n_ataque)
        fwd_pkts_scan = np.random.choice([1, 2], size=n_ataque, p=[0.85, 0.15])
        bwd_pkts_scan = np.random.choice([0, 1], size=n_ataque, p=[0.80, 0.20])
        bytes_s_scan = (fwd_pkts_scan * 40.0) / (duracao_scan / 1000.0)
        pkts_s_scan = (fwd_pkts_scan + bwd_pkts_scan) / (duracao_scan / 1000.0)

        df_ataque = pd.DataFrame({
            'Flow Duration': duracao_scan,
            'Total Fwd Packets': fwd_pkts_scan,
            'Total Backward Packets': bwd_pkts_scan,
            'Total Length of Fwd Packets': fwd_pkts_scan * 40.0,
            'Total Length of Bwd Packets': bwd_pkts_scan * 40.0,
            'Flow Bytes/s': bytes_s_scan,
            'Flow Packets/s': pkts_s_scan,
            'Flow IAT Mean': duracao_scan,
            'Fwd Packet Length Max': 40.0,
            'Fwd Packet Length Min': 40.0,
            'Packet Length Mean': 40.0,
            'ACK Flag Count': np.random.binomial(1, 0.03, n_ataque),
            'SYN Flag Count': np.random.binomial(1, 0.97, n_ataque),
            'Label': 'PortScan'
        })
        df_consolidado = pd.concat([df_benign, df_ataque], ignore_index=True)
    else:
        # 2. Perfil DDoS (Volumetria densa / DoS Hulk)
        duracao_ddos = np.random.normal(loc=1500.0, scale=250.0, size=n_ataque)
        duracao_ddos = np.clip(duracao_ddos, 80.0, None)
        fwd_pkts_ddos = np.random.poisson(lam=75, size=n_ataque) + 25
        bwd_pkts_ddos = np.random.poisson(lam=3, size=n_ataque)
        bytes_s_ddos = (fwd_pkts_ddos * 1440.0) / (duracao_ddos / 1000.0)
        pkts_s_ddos = (fwd_pkts_ddos + bwd_pkts_ddos) / (duracao_ddos / 1000.0)

        df_ataque = pd.DataFrame({
            'Flow Duration': duracao_ddos,
            'Total Fwd Packets': fwd_pkts_ddos,
            'Total Backward Packets': bwd_pkts_ddos,
            'Total Length of Fwd Packets': fwd_pkts_ddos * 1440.0,
            'Total Length of Bwd Packets': bwd_pkts_ddos * 50.0,
            'Flow Bytes/s': bytes_s_ddos,
            'Flow Packets/s': pkts_s_ddos,
            'Flow IAT Mean': duracao_ddos / (fwd_pkts_ddos + 1.0),
            'Fwd Packet Length Max': 1460.0,
            'Fwd Packet Length Min': 450.0,
            'Packet Length Mean': 1250.0 + np.random.normal(0, 25, n_ataque),
            'ACK Flag Count': np.random.binomial(1, 0.96, n_ataque),
            'SYN Flag Count': np.random.binomial(1, 0.04, n_ataque),
            'Label': 'DDoS'
        })
        df_consolidado = pd.concat([df_benign, df_ataque], ignore_index=True)

    # Inclusão de metadados topológicos e atributos constantes para teste do Bloco 2
    df_consolidado['Flow ID'] = [f"FLOW_ID_{i}" for i in range(len(df_consolidado))]
    df_consolidado['Source IP'] = '192.168.10.50'
    df_consolidado['Source Port'] = np.random.randint(1024, 65535, len(df_consolidado))
    df_consolidado['Destination IP'] = '172.16.0.1'
    df_consolidado['Destination Port'] = 80 if tipo_cenario == "ddos" else np.random.randint(1, 1024, len(df_consolidado))
    df_consolidado['Timestamp'] = '2017-07-07 15:00:00'
    df_consolidado['Bwd PSH Flags'] = 0.0  # Atributo com variancia zero intencional

    return df_consolidado.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


# ==================================================================================================
# BLOCO 2: PREVENCAO DE DATA LEAKAGE E SELECAO DE FEATURES
# ==================================================================================================

def prevenir_leakage_e_selecionar_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Remove identificadores de topologia fisica e filtra preditores com variancia estritamente nula.

    Razao Tecnica e Justificativa Estatistica:
    1. Prevenção de Data Leakage Topológico:
       Os campos 'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port' e 'Timestamp'
       representam metadados circunstanciais da bancada de teste do CICIDS2017. A manutencao desses dados
       induz o algoritmo de agrupamento a particionar conexoes pelo endereco IP do host ou pela porta do
       servidor alvo, decorando a topologia em vez de aprender padroes comportamentais invariantes
       (cadencia de pacotes, relacoes de payload, assimetria de fluxo).

    2. Segregacao Estrita do Ground Truth (Label):
       O rotulo 'Label' e imediatamente extraido e preservado fora do espaco de features de treinamento.
       A inferencia de agrupamento e estritamente cega (nao supervisionada). O rotulo e utilizado
       unicamente em estagio posterior para validacao externa via Adjusted Rand Index (ARI).

    3. Eliminacao de Variancia Zero (VarianceThreshold = 0.0):
       Features onde Var(X) = 0 possuem entropia nula e informacao mutua zero. No calculo da distancia
       euclidiana d = sqrt(sum((pi - qi)^2)), diferencas nestas dimensoes sao identicamente nulas,
       adicionando apenas sobrecarga computacional de processamento e alocacao de memoria inerte.

    Entradas:
        df (pd.DataFrame): Dados originais carregados.

    Saidas:
        Tuple[pd.DataFrame, pd.Series]: Matriz de features puras (X) e vetor de rotulos reais (y).
    """
    df_work = df.copy()

    # Identificadores topologicos que provocam data leakage
    colunas_identificacao = [
        'Flow ID', 'Source IP', 'Source Port',
        'Destination IP', 'Destination Port', 'Timestamp',
        'SimillarHTTP'
    ]
    colunas_removidas = [c for c in colunas_identificacao if c in df_work.columns]
    df_work = df_work.drop(columns=colunas_removidas, errors='ignore')
    print(f"[INFO] Expurgo de colunas de leakage topologico: {colunas_removidas}")

    # Segregacao do rotulo supervisionado
    if 'Label' in df_work.columns:
        y = df_work['Label'].copy()
        df_work = df_work.drop(columns=['Label'])
        print("[INFO] Segregacao de rotulo Label concluida com sucesso para avaliacao cega.")
    else:
        y = pd.Series(['Desconhecido'] * len(df_work), name='Label')
        print("[AVISO] Atributo Label ausente. Operacao em modo puramente nao rotulado.")

    # Filtra exclusivamente colunas de natureza quantitativa
    colunas_numericas = df_work.select_dtypes(include=[np.number]).columns
    df_num = df_work[colunas_numericas]

    # Remocao de atributos invariantes (variancia zero)
    seletor_var = VarianceThreshold(threshold=0.0)
    seletor_var.fit(df_num)
    colunas_validas = df_num.columns[seletor_var.get_support()]
    descartadas_var = df_num.columns[~seletor_var.get_support()].tolist()

    df_selecionado = df_num[colunas_validas]
    print(
        f"[INFO] Selecao de features: {len(descartadas_var)} atributos com variancia zero eliminados. "
        f"Restam {df_selecionado.shape[1]} atributos informativos."
    )

    return df_selecionado, y


# ==================================================================================================
# BLOCO 3: AMOSTRAGEM ESTRATIFICADA
# ==================================================================================================

def realizar_amostragem(
    X: pd.DataFrame,
    y: pd.Series,
    n_samples: int = 10000,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Subamostra o conjunto de dados preservando a proporcao de classes anomalas para contornar a
    complexidade quadratica do DBSCAN.

    Fundamentacao de Complexidade:
    O DBSCAN computa as distancias para todos os pontos vizinhos dentro do raio eps.
    Em um espaco de D dimensoes com N instancias, a construcao de matrizes de distancia completa impoe
    complexidade de espaco S(N) = O(N^2) e complexidade de tempo T(N) = O(D * N^2).
    Para N = 2.830.000 conexoes (tamanho do CICIDS2017 completo), uma matriz float64 exigiria
    mais de 60 Terabytes de memoria volatil. A subamostragem estratificada preserva a densidade
    relativa e a probabilidade marginal P(Ataque), assegurando fidelidade estatistica sob O(n_samples^2).
    """
    total = len(X)
    if total <= n_samples:
        print(f"[INFO] Amostragem nao requerida: total de conexoes ({total}) inferior ao limite ({n_samples}).")
        return X.copy(), y.copy()

    print(f"[INFO] Reducao de escala por amostragem: {total} -> {n_samples} instancias (mitigacao O(N^2)).")

    try:
        X_sub, _, y_sub, _ = train_test_split(
            X, y,
            train_size=n_samples,
            stratify=y,
            random_state=random_state
        )
    except Exception as e:
        print(f"[AVISO] Falha na estratificacao ({e}). Aplicando amostragem uniforme uniforme.")
        X_sub = X.sample(n=n_samples, random_state=random_state)
        y_sub = y.loc[X_sub.index]

    return X_sub.reset_index(drop=True), y_sub.reset_index(drop=True)


# ==================================================================================================
# BLOCO 4: PADRONIZACAO (STANDARDSCALER)
# ==================================================================================================

def padronizar_features(X: pd.DataFrame) -> Tuple[np.ndarray, StandardScaler]:
    """
    Normaliza a matriz de atributos segundo a transformacao Z-score: z = (x - mu) / sigma.

    Fundamentacao Matematica:
    A formulacao da distancia euclidiana entre duas conexoes p e q:
      d(p, q) = sqrt( sum_{j=1}^{D} (p_j - q_j)^2 )
    e linearmente dependente da escala de variacao absoluta de cada dimensao.
    No tráfego de rede, 'Flow Duration' e 'Flow Bytes/s' atingem ordens de grandeza de 10^7,
    enquanto flags de controle TCP e indicadores de pacotes operam no intervalo discreto [0, 1].
    Sem padronizacao, as diferencas nas dimensoes de bytes dominam mais de 99.9% da norma euclidiana,
    anulando completamente o efeito discriminativo das flags e cadencias de pacotes.
    A transformacao Z-score centraliza cada vetor em media zero e variancia unitaria.
    """
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print(f"[INFO] Padronizacao Z-score aplicada sobre {X.shape[1]} atributos (mu=0.0, sigma=1.0).")
    return X_scaled, scaler


# ==================================================================================================
# BLOCO 5: ESTIMATIVA ANALITICA DO EPSILON (K-DISTANCE GRAPH)
# ==================================================================================================

def estimar_joelho_k_distance(
    X_scaled: np.ndarray,
    k: Optional[int] = None
) -> Tuple[float, np.ndarray, int, int]:
    """
    Calcula o k-distance graph e identifica analiticamente o ponto de joelho (cotovelo) para estimativa
    otima do hiperparametro epsilon do DBSCAN.

    Fundamentacao Matematica e Heuristica de Selecao:
    1. Heuristica da Dimensionalidade:
       Conforme postulado por Ester et al. (1996) e consolidado por Schubert et al. (2017),
       para espacos multidimensionais contínuos, fixa-se k = 2 * d (onde d e a dimensionalidade de features).
       Isso confere robustez estatistica a determinacao de densidade local contra flutuacoes locais.

    2. Deteccao Analitica do Cotovelo (Maxima Distancia Ortogonal a Linha Secante):
       Apos ordenar as k-distancias d_0 <= d_1 <= ... <= d_{N-1}, define-se a linha secante ligando o
       ponto inicial (0, d_0) ao ponto final (N-1, d_{N-1}). Normalizando os eixos para [0, 1] x [0, 1]:
         x_norm_i = i / (N - 1)
         y_norm_i = (d_i - d_0) / (d_{N-1} - d_0)
       A distancia vertical/ortogonal a reta diagonal ideal y = x e dada por:
         dist_i = y_norm_i - x_norm_i
       O indice i* que minimiza essa diferenca (maior distanciamento perpendicular abaixo da secante)
       ou que maximiza a curvatura geometrica assinala a transicao de fase de densidade entre o agrupamento
       coeso (clusters) e o regime de espalhamento asfixiado por baixa densidade (ruido).
       O valor d_{i*} e retornado como estimativa otimizada de epsilon.

    Entradas:
        X_scaled (np.ndarray): Matriz normalizada de dimensoes N x D.
        k (Optional[int]): Numero de vizinhos. Se None, assume k = 2 * D.

    Saidas:
        Tuple[float, np.ndarray, int, int]: (eps_otimo, distancias_ordenadas, indice_joelho, k_utilizado)
    """
    n_pontos, n_dimensoes = X_scaled.shape

    if k is None:
        # Heuristica k = 2 * d, limitada a no maximo n_pontos - 1
        k = min(max(4, 2 * n_dimensoes), n_pontos - 1)

    print(f"[INFO] Calculando k-distance graph com k={k} (heuristica 2*dimensoes, d={n_dimensoes})...")

    # Ajuste de vizinhos mais proximos
    nn = NearestNeighbors(n_neighbors=k, algorithm='auto', metric='euclidean', n_jobs=-1)
    nn.fit(X_scaled)
    distances, _ = nn.kneighbors(X_scaled)

    # Extrai a distancia para o k-esimo vizinho (ultima coluna) e ordena em ordem crescente
    k_distances = distances[:, -1]
    distancias_ordenadas = np.sort(k_distances)

    # Deteccao analitica do joelho atraves da projecao ortogonal normalizada
    n = len(distancias_ordenadas)
    x_coords = np.arange(n)
    y_coords = distancias_ordenadas

    # Normalizacao no espaco unitario [0, 1]
    x_norm = x_coords / (n - 1)
    y_range = y_coords[-1] - y_coords[0]
    if y_range == 0:
        y_range = 1e-9
    y_norm = (y_coords - y_coords[0]) / y_range

    # A reta secante no espaco normalizado e a identidade y = x.
    # O ponto onde a curva mais se afasta da reta secante (maior deflexao convexa) representa o cotovelo.
    # Em curvas convexas ascendentes, x_norm - y_norm atinge valor maximo positivo no joelho.
    desvios = x_norm - y_norm
    indice_joelho = int(np.argmax(desvios))

    eps_estimado = float(distancias_ordenadas[indice_joelho])
    print(f"[INFO] Ponto de joelho detectado no indice {indice_joelho}/{n}: epsilon sugerido = {eps_estimado:.4f}")

    return eps_estimado, distancias_ordenadas, indice_joelho, k


def plotar_e_salvar_k_distance(
    distancias_ordenadas: np.ndarray,
    indice_joelho: int,
    eps_estimado: float,
    k: int,
    caminho_saida: str = "reports/figures/k_distance_graph.png"
) -> str:
    """
    Gera e salva o grafico tecnico da curva de k-distancia com marcacao vetorial do cotovelo.
    """
    dir_fig = Path(caminho_saida).parent
    dir_fig.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(10, 6), dpi=300)
    plt.plot(distancias_ordenadas, color='#1E3A8A', linewidth=2.0, label=f'k-distancia (k={k})')

    # Marcacao da linha de transicao do cotovelo
    plt.axhline(
        y=eps_estimado,
        color='#DC2626',
        linestyle='--',
        linewidth=1.5,
        label=f'Epsilon Estimado (Joelho) = {eps_estimado:.4f}'
    )
    plt.axvline(
        x=indice_joelho,
        color='#64748B',
        linestyle=':',
        linewidth=1.2,
        label=f'Indice de Inflexao ({indice_joelho})'
    )
    plt.scatter(
        [indice_joelho],
        [eps_estimado],
        color='#DC2626',
        s=80,
        zorder=5
    )

    plt.title(f"Curva de k-Distancia para Determinacao de Epsilon (CICIDS2017, k={k})", fontsize=12, fontweight='bold')
    plt.xlabel("Indice das Conexoes Ordenadas por Proximidade", fontsize=10)
    plt.ylabel(f"Distancia Euclidiana ao {k}-esimo Vizinho Mais Proximo", fontsize=10)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend(loc='upper left', frameon=True)
    plt.tight_layout()

    plt.savefig(caminho_saida, format='png', dpi=300)
    plt.close()

    print(f"[INFO] Grafico do k-distance graph salvo em: {caminho_saida}")
    return caminho_saida


# ==================================================================================================
# BLOCO 6: MODELO BASELINE — K-MEANS
# ==================================================================================================

def executar_baseline_kmeans(
    X_scaled: np.ndarray,
    y_true: pd.Series,
    k: int = 3,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Ajusta o particionamento K-Means como referencia comparativa para avaliacao estrutural.

    Justificativas Estatisticas e Inadequacao:
    1. Hipotese de Esfericidade e Isotropia:
       O K-Means minimiza a soma dos quadrados intra-cluster (Inercia). Esta formulacao penaliza
       quadraticamente a distancia ao centroide, impondo fronteiras de decisao estritamente lineares
       (poligonos de Voronoi) e agrupamentos hiper-esfericos de mesma variancia.
       O tráfego de ataques em cibersegurança manifesta densidades fortemente assimetricas e
       geometrias filamentosas que o K-Means fragmenta incorretamente.

    2. Incapacidade de Isolamento de Ruido:
       O algoritmo forca cada anomalia ou conexao desconhecida a ingressar no centroide mais proximo,
       corrompendo o vetor medio do agrupamento legitimate com dados maliciosos pontuais.
    """
    print(f"\n[INFO] --- EXECUTANDO MODELO BASELINE: K-MEANS (k={k}) ---")
    kmeans = KMeans(n_clusters=k, init='k-means++', n_init=10, random_state=random_state)
    labels_kmeans = kmeans.fit_predict(X_scaled)

    silhueta = float(silhouette_score(X_scaled, labels_kmeans))
    ari = float(adjusted_rand_score(y_true, labels_kmeans))
    inercia = float(kmeans.inertia_)
    db_index = float(davies_bouldin_score(X_scaled, labels_kmeans))

    print(f"[RESULTADO BASELINE] Silhouette Score: {silhueta:.4f}")
    print(f"[RESULTADO BASELINE] Adjusted Rand Index (ARI): {ari:.4f}")
    print(f"[RESULTADO BASELINE] Davies-Bouldin Index: {db_index:.4f}")
    print(f"[RESULTADO BASELINE] Inercia Intra-Cluster: {inercia:.2f}")

    return {
        'modelo': kmeans,
        'labels': labels_kmeans,
        'silhouette': silhueta,
        'ari': ari,
        'davies_bouldin': db_index,
        'inercia': inercia,
        'k': k
    }


# ==================================================================================================
# BLOCO 7: MODELO PRINCIPAL — DBSCAN
# ==================================================================================================

def executar_dbscan(
    X_scaled: np.ndarray,
    y_true: pd.Series,
    eps: float = 1.8,
    min_samples: int = 15
) -> Dict[str, Any]:
    """
    Executa o algoritmo DBSCAN para descoberta de grupos de densidade arbitraria e isolamento de anomalias.

    Tratamento Matematico de Ruido na Avaliacao:
    O rotulo -1 do DBSCAN define conexoes que nao atingiram a cardinalidade minima min_samples dentro da
    bola de raio eps. Pontos com rotulo -1 nao constituem um agrupamento geometrico unificado (sao
    desconexos entre si). Portanto, o Coeficiente de Silhueta, que avalia a relacao (b_i - a_i) / max(a_i, b_i),
    deve ser computado com rigor restrito aos pontos pertencentes aos nucleos densos (labels != -1),
    evitando que a dispersao aleatoria do ruido penalize indevidamente a coesao dos clusters legitimos.
    """
    print(f"\n[INFO] --- EXECUTANDO MODELO PRINCIPAL: DBSCAN (eps={eps:.4f}, min_samples={min_samples}) ---")
    dbscan = DBSCAN(eps=eps, min_samples=min_samples, n_jobs=-1)
    labels_dbscan = dbscan.fit_predict(X_scaled)

    labels_validos = labels_dbscan[labels_dbscan != -1]
    n_clusters = len(np.unique(labels_validos))
    n_ruido = int(np.sum(labels_dbscan == -1))
    pct_ruido = float((n_ruido / len(labels_dbscan)) * 100.0)

    print(f"[RESULTADO DBSCAN] Agrupamentos densos identificados: {n_clusters}")
    print(f"[RESULTADO DBSCAN] Conexoes isoladas como Ruido/Anomalia (-1): {n_ruido} ({pct_ruido:.2f}%)")

    ari = float(adjusted_rand_score(y_true, labels_dbscan))
    print(f"[RESULTADO DBSCAN] Adjusted Rand Index (ARI): {ari:.4f}")

    # Silhueta e Davies-Bouldin sobre clusters validos (sem ruido)
    silhueta_core = None
    db_index_core = None
    mascara_core = (labels_dbscan != -1)

    if n_clusters >= 2 and np.sum(mascara_core) > n_clusters:
        silhueta_core = float(silhouette_score(X_scaled[mascara_core], labels_dbscan[mascara_core]))
        db_index_core = float(davies_bouldin_score(X_scaled[mascara_core], labels_dbscan[mascara_core]))
        print(f"[RESULTADO DBSCAN] Silhouette Score (clusters densos sem ruido): {silhueta_core:.4f}")
        print(f"[RESULTADO DBSCAN] Davies-Bouldin Index (sem ruido): {db_index_core:.4f}")
    else:
        print("[AVISO] Silhueta dos nucleos nao calculada (quantidade de clusters densos < 2).")

    # Matriz de contingencia
    df_analise = pd.DataFrame({
        'Cluster_DBSCAN': labels_dbscan,
        'Tipo_Trafego_Real': y_true
    })
    tabela_distribuicao = pd.crosstab(
        df_analise['Cluster_DBSCAN'],
        df_analise['Tipo_Trafego_Real'],
        margins=True,
        margins_name="Total"
    )

    print("\n[MATRIZ DE CONTINGENCIA] Distribuicao do Trafego Real por Cluster:")
    print(tabela_distribuicao.to_string())

    return {
        'modelo': dbscan,
        'labels': labels_dbscan,
        'n_clusters': n_clusters,
        'n_ruido': n_ruido,
        'pct_ruido': pct_ruido,
        'silhouette_core': silhueta_core,
        'davies_bouldin_core': db_index_core,
        'ari': ari,
        'tabela_distribuicao': tabela_distribuicao,
        'eps': eps,
        'min_samples': min_samples
    }


# ==================================================================================================
# BLOCO 8: EXPORTACAO DE RELATORIOS E ARTEFATOS JSON
# ==================================================================================================

def salvar_relatorios_analiticos(
    res_kmeans: Dict[str, Any],
    res_dbscan: Dict[str, Any],
    info_kdist: Dict[str, Any],
    cenario: str,
    n_amostras: int,
    n_features: int,
    caminho_dir: str = "reports"
) -> Tuple[str, str]:
    """
    Serializa e grava os resultados das metricas e a matriz de contingencia em arquivos JSON estruturados.
    """
    diretorio = Path(caminho_dir)
    diretorio.mkdir(parents=True, exist_ok=True)

    caminho_metricas = diretorio / "metrics_summary.json"
    caminho_contingencia = diretorio / "contingency_matrix.json"

    # Estruturacao do resumo de metricas
    dados_metricas = {
        "projeto": "CyberCluster",
        "cenario_trafego": cenario,
        "instancias_analisadas": n_amostras,
        "dimensionalidade_espaco": n_features,
        "estimativa_k_distance": {
            "k_utilizado": info_kdist["k"],
            "indice_joelho": info_kdist["indice_joelho"],
            "epsilon_otimo_sugerido": info_kdist["eps_estimado"],
            "grafico_gerado": "reports/figures/k_distance_graph.png"
        },
        "baseline_kmeans": {
            "k_clusters": res_kmeans["k"],
            "silhouette_score": res_kmeans["silhouette"],
            "adjusted_rand_index": res_kmeans["ari"],
            "davies_bouldin_index": res_kmeans["davies_bouldin"],
            "inercia": res_kmeans["inercia"],
            "taxa_ruido": 0.0
        },
        "modelo_dbscan": {
            "epsilon_aplicado": res_dbscan["eps"],
            "min_samples": res_dbscan["min_samples"],
            "clusters_densos_encontrados": res_dbscan["n_clusters"],
            "conexoes_ruido_absoluto": res_dbscan["n_ruido"],
            "percentual_ruido": res_dbscan["pct_ruido"],
            "silhouette_score_core": res_dbscan["silhouette_core"],
            "davies_bouldin_index_core": res_dbscan["davies_bouldin_core"],
            "adjusted_rand_index": res_dbscan["ari"]
        }
    }

    with open(caminho_metricas, 'w', encoding='utf-8') as f:
        json.dump(dados_metricas, f, indent=4, ensure_ascii=False)
    print(f"[INFO] Relatorio de metricas salvo com sucesso em: {caminho_metricas}")

    # Estruturacao da matriz de contingencia
    tabela = res_dbscan["tabela_distribuicao"]
    contingencia_dict = {
        str(idx): {str(col): int(val) for col, val in row.items()}
        for idx, row in tabela.iterrows()
    }

    with open(caminho_contingencia, 'w', encoding='utf-8') as f:
        json.dump(contingencia_dict, f, indent=4, ensure_ascii=False)
    print(f"[INFO] Matriz de contingencia salva com sucesso em: {caminho_contingencia}")

    return str(caminho_metricas), str(caminho_contingencia)


# ==================================================================================================
# FUNCAO PRINCIPAL (ORQUESTRADOR)
# ==================================================================================================

def executar_pipeline_completo(
    caminho_csv: str = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    cenario: str = "ddos",
    n_amostras: int = 10000,
    eps: Optional[float] = None,
    min_samples: int = 15,
    salvar_amostra_processada: bool = True
) -> Dict[str, Any]:
    """
    Executa sequencialmente todas as etapas de sanitizacao, estimativa geometrica,
    modelagem e persistencia do pipeline CyberCluster.
    """
    print("=" * 80)
    print(" PIPELINE ANALITICO CYBERCLUSTER - CICIDS2017")
    print(f" CENARIO: {cenario.upper()} | INSTANCIAS: {n_amostras}")
    print("=" * 80)

    # 1. Ingestao e Limpeza
    df_bruto = carregar_dados(caminho_csv, tipo_cenario=cenario, permitir_amostra_sintetica=True)

    # 2. Segregacao de Leakage e Selecao de Atributos
    X_limpo, y = prevenir_leakage_e_selecionar_features(df_bruto)

    # 3. Amostragem Estratificada
    X_sample, y_sample = realizar_amostragem(X_limpo, y, n_samples=n_amostras)

    # 4. Padronizacao Z-Score
    X_scaled, scaler = padronizar_features(X_sample)

    # 5. Estimativa de Joelho via k-distance graph (k = 2 * d)
    eps_sugerido, dists_ordenadas, idx_joelho, k_utilizado = estimar_joelho_k_distance(X_scaled)
    plotar_e_salvar_k_distance(dists_ordenadas, idx_joelho, eps_sugerido, k=k_utilizado)

    info_kdist = {
        "k": k_utilizado,
        "eps_estimado": eps_sugerido,
        "indice_joelho": idx_joelho,
        "distancias_ordenadas": dists_ordenadas
    }

    # Se eps nao foi explicitamente forçado pelo usuario, adota o valor analitico do joelho
    eps_final = eps if eps is not None else eps_sugerido

    # 6. Baseline: K-Means
    res_kmeans = executar_baseline_kmeans(X_scaled, y_sample, k=3)

    # 7. Modelo Principal: DBSCAN
    res_dbscan = executar_dbscan(X_scaled, y_sample, eps=eps_final, min_samples=min_samples)

    # 8. Salvamento de Relatorios Estruturados JSON em reports/
    salvar_relatorios_analiticos(
        res_kmeans=res_kmeans,
        res_dbscan=res_dbscan,
        info_kdist=info_kdist,
        cenario=cenario,
        n_amostras=n_amostras,
        n_features=X_sample.shape[1],
        caminho_dir="reports"
    )

    # 9. Persistencia de Dados Processados
    if salvar_amostra_processada:
        dir_proc = Path("data/processed")
        dir_proc.mkdir(parents=True, exist_ok=True)
        df_export = X_sample.copy()
        df_export['True_Label'] = y_sample.values
        df_export['Cluster_KMeans'] = res_kmeans['labels']
        df_export['Cluster_DBSCAN'] = res_dbscan['labels']

        caminho_export = dir_proc / f"amostra_{cenario}.parquet"
        try:
            df_export.to_parquet(caminho_export, index=False)
            print(f"[INFO] Amostra enriquecida salva em: {caminho_export}")
        except Exception:
            caminho_csv_export = dir_proc / f"amostra_{cenario}.csv"
            df_export.to_csv(caminho_csv_export, index=False)
            print(f"[INFO] Amostra enriquecida salva em: {caminho_csv_export}")

    print("\n" + "=" * 80)
    print(" QUADRO COMPARATIVO TECNICO DE DESEMPENHO")
    print("=" * 80)
    sil_core_str = f"{res_dbscan['silhouette_core']:.4f}" if res_dbscan['silhouette_core'] is not None else "N/A"
    print(f"| {'Metrica':<35} | {'K-Means (k=3)':<18} | {f'DBSCAN (eps={eps_final:.2f})':<18} |")
    print(f"|{'-' * 37}|{'-' * 20}|{'-' * 20}|")
    print(f"| {'Silhouette Score':<35} | {res_kmeans['silhouette']:<18.4f} | {sil_core_str:<18} |")
    print(f"| {'Adjusted Rand Index (ARI)':<35} | {res_kmeans['ari']:<18.4f} | {res_dbscan['ari']:<18.4f} |")
    print(f"| {'Davies-Bouldin Index':<35} | {res_kmeans['davies_bouldin']:<18.4f} | {res_dbscan['davies_bouldin_core'] or 0.0:<18.4f} |")
    print(f"| {'Taxa de Ruido':<35} | {'0.00%':<18} | {res_dbscan['pct_ruido']:<17.2f}% |")
    print(f"| {'Tratamento de Outliers':<35} | {'Inexistente':<18} | {'Nativo (Cluster -1)':<18} |")
    print("=" * 80)

    return {
        'X_sample': X_sample,
        'y_sample': y_sample,
        'X_scaled': X_scaled,
        'scaler': scaler,
        'k_distance': info_kdist,
        'kmeans': res_kmeans,
        'dbscan': res_dbscan
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline Analitico CyberCluster")
    parser.add_argument("--cenario", type=str, default="ddos", choices=["ddos", "portscan", "misto"],
                        help="Perfil de ataque do CICIDS2017: ddos, portscan ou misto")
    parser.add_argument("--csv", type=str, default=None,
                        help="Caminho explicito para o CSV bruto do CICIDS2017")
    parser.add_argument("--amostras", type=int, default=10000,
                        help="Volume de conexoes para amostragem")
    parser.add_argument("--eps", type=float, default=None,
                        help="Hiperparametro epsilon do DBSCAN (se omitido, usa estimativa do joelho)")
    parser.add_argument("--min_samples", type=int, default=15,
                        help="Hiperparametro min_samples do DBSCAN")

    args = parser.parse_args()

    caminho_csv_definido = args.csv
    if caminho_csv_definido is None:
        if args.cenario == "portscan":
            caminho_csv_definido = "data/raw/Friday-WorkingHours-Morning-PortScan.pcap_ISCX.csv"
        elif args.cenario == "misto":
            caminho_csv_definido = "data/raw/Friday-WorkingHours-Combined.csv"
        else:
            caminho_csv_definido = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

    executar_pipeline_completo(
        caminho_csv=caminho_csv_definido,
        cenario=args.cenario,
        n_amostras=args.amostras,
        eps=args.eps,
        min_samples=args.min_samples
    )
