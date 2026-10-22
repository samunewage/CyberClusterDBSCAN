"""
====================================================================================================
PROJETO CYBERCLUSTER - INTERFACE ANALITICA INTERATIVA (STREAMLIT)
====================================================================================================

MODULO: app/app.py
AUTORES: Samuel Esperanca Vieira Panobianco, Bryan Williams Souto Silva,
         Lucas Miguel Cardoso de Almeida, Renan Denadai de Paul.
INSTITUICAO: Faculdades Integradas de Bauru (FIB)
DISCIPLINA: Inteligencia Artificial II

1. OBJETIVO DA APLICAÇÃO:
----------------------------------------------------------------------------------------------------
Este modulo prove uma estacao de trabalho interativa para avaliacao de modelos de agrupamento nao
supervisionados aplicados a fluxos de tráfego do benchmark CICIDS2017. O sistema permite calibracao
dinamica de densidade euclidiana (DBSCAN), analise comparativa de cenarios isolados e de Trafego
Misto (Normal + DDoS + PortScan), inspecao da curva de k-distancias para estimativa do cotovelo de
epsilon, projecao espacial via Analise de Componentes Principais (PCA) e simulacao continua com
atualizacao em loop para monitoramento dinâmico em tempo real.

2. CONTROLES E FLUXO OPERACIONAL:
----------------------------------------------------------------------------------------------------
- Seletor de Cenario:
  * Trafego Misto (Normal + DDoS + PortScan)
  * DDoS (Friday Afternoon)
  * PortScan (Friday Morning)
- Modo de Simulacao Continua: Execucao em loop temporal com atualizacao automatica de graficos e metricas.
- Calibracao de Densidade: Controles deslizantes para Epsilon e Min_Samples.
- Estimativa Geometrica: Calculo analitico do joelho da curva de k-distancias com k=2*d.
- Painel de KPIs: Metricas de coesao interna (Silhouette, Davies-Bouldin) e externas (ARI).
- Projecao Ortogonal 2D: Mapeamento em espaco latente via PCA com isolamento visual de anomalias (ruido -1).
- Exportacao Estruturada: Download de relatorios em formato JSON (padrao reports/).

====================================================================================================
"""

import sys
import time
import json
from pathlib import Path

# Inclusao do diretorio raiz no caminho de resolucao de modulos
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN, KMeans
from sklearn.metrics import silhouette_score, adjusted_rand_score, davies_bouldin_score

from src.pipeline import (
    carregar_dados,
    prevenir_leakage_e_selecionar_features,
    realizar_amostragem,
    padronizar_features,
    estimar_joelho_k_distance,
    gerar_dataset_sintetico_cicids2017
)


# ==================================================================================================
# CONFIGURACAO DE PAGINA E ESTILIZACAO VISUAL SOBRIA
# ==================================================================================================

st.set_page_config(
    page_title="CyberCluster | Analise Nao Supervisionada CICIDS2017",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilizacao CSS profissional, estritamente tecnica e sem icones/emojis
st.markdown("""
<style>
    .reportview-container .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    .header-title {
        font-size: 1.8rem;
        font-weight: 700;
        color: #0F172A;
        letter-spacing: -0.02em;
        margin-bottom: 0.2rem;
    }
    .header-subtitle {
        font-size: 0.95rem;
        color: #475569;
        margin-bottom: 1.5rem;
        line-height: 1.4;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.6rem !important;
        font-weight: 700;
        color: #0F172A;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
        font-weight: 600;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 1.5rem;
        border-bottom: 1px solid #E2E8F0;
    }
    .stTabs [data-baseweb="tab"] {
        height: 44px;
        font-weight: 600;
        font-size: 0.9rem;
        color: #475569;
    }
    .stTabs [aria-selected="true"] {
        color: #1E3A8A !important;
        border-bottom-color: #1E3A8A !important;
    }
</style>
""", unsafe_allow_html=True)


# ==================================================================================================
# FUNCOES COM CACHE DE PERFORMANCE
# ==================================================================================================

@st.cache_data(show_spinner="Carregando e processando base de fluxos...")
def carregar_dados_cenario(cenario: str, n_amostras: int):
    """
    Executa a ingestao, saneamento numerico, segregacao de leakage e amostragem estratificada.
    """
    if cenario == "ddos":
        caminho_csv = "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    elif cenario == "portscan":
        caminho_csv = "data/raw/Friday-WorkingHours-Morning-PortScan.pcap_ISCX.csv"
    else:
        caminho_csv = "data/raw/Friday-WorkingHours-Combined.csv"

    df_bruto = carregar_dados(caminho_csv, tipo_cenario=cenario, permitir_amostra_sintetica=True)
    X_limpo, y = prevenir_leakage_e_selecionar_features(df_bruto)
    X_sample, y_sample = realizar_amostragem(X_limpo, y, n_samples=n_amostras)
    X_scaled, scaler = padronizar_features(X_sample)

    # Estimativa analitica de joelho k-distance (k = 2 * d)
    eps_sugerido, dists_ordenadas, idx_joelho, k_utilizado = estimar_joelho_k_distance(X_scaled)

    return {
        "X_sample": X_sample,
        "y_sample": y_sample,
        "X_scaled": X_scaled,
        "eps_sugerido": eps_sugerido,
        "dists_ordenadas": dists_ordenadas,
        "idx_joelho": idx_joelho,
        "k_utilizado": k_utilizado
    }


def gerar_lote_streaming(cenario: str, n_amostras: int, seed: int):
    """
    Gera um lote pontual de conexoes com variacao estocastica controlada para a simulacao continua.
    """
    df_raw = gerar_dataset_sintetico_cicids2017(n_samples=n_amostras, tipo_cenario=cenario, random_state=seed)
    X_clean, y = prevenir_leakage_e_selecionar_features(df_raw)
    X_scaled, _ = padronizar_features(X_clean)
    return X_clean, y, X_scaled


@st.cache_data(show_spinner="Computando agrupamento DBSCAN...")
def computar_dbscan(X_scaled: np.ndarray, eps: float, min_samples: int):
    """
    Executa o DBSCAN sobre o espaco vetorial normalizado.
    """
    modelo = DBSCAN(eps=eps, min_samples=min_samples, n_jobs=-1)
    labels = modelo.fit_predict(X_scaled)
    return labels


@st.cache_data(show_spinner="Calculando decomposicao ortogonal PCA...")
def computar_pca_2d(X_scaled: np.ndarray):
    """
    Calcula os dois eixos principais de maior variancia explicada.
    """
    pca = PCA(n_components=2, random_state=42)
    componentes = pca.fit_transform(X_scaled)
    return componentes, pca.explained_variance_ratio_


# ==================================================================================================
# BARRA LATERAL (CONTROLES PARAMETRICOS)
# ==================================================================================================

with st.sidebar:
    st.markdown("### CyberCluster")
    st.caption("Painel de Agrupamento Nao Supervisionado")
    st.markdown("---")

    # 1. Seletor de Cenario
    cenario_selecionado = st.selectbox(
        "Cenario de Trafego (CICIDS2017):",
        options=["misto", "ddos", "portscan"],
        format_func=lambda x: {
            "misto": "Trafego Misto (Normal + DDoS + PortScan)",
            "ddos": "DDoS (Friday Afternoon)",
            "portscan": "PortScan (Friday Morning)"
        }[x],
        help="Permite avaliar ataques isolados ou a coexistencia simultanea de multiplas ameacas."
    )

    tamanho_amostra = st.select_slider(
        "Volume Amostral:",
        options=[2000, 5000, 8000, 10000, 15000],
        value=5000,
        help="Quantidade de conexoes subamostradas para controle de latencia computacional."
    )

    # Carregamento previo dos dados para capturar o epsilon sugerido pelo k-distance graph
    dados_processados = carregar_dados_cenario(cenario_selecionado, tamanho_amostra)
    eps_sugerido_calculado = dados_processados["eps_sugerido"]

    st.markdown("---")
    st.markdown("### Hiperparametros DBSCAN")

    eps_input = st.slider(
        "Raio de Densidade (Epsilon):",
        min_value=0.1,
        max_value=5.0,
        value=float(round(eps_sugerido_calculado, 2)),
        step=0.05,
        help="Raio maximo da hiperesfera para inclusao de vizinhos no espaco vetorial."
    )

    min_samples_input = st.slider(
        "Cardinalidade Minima (Min_Samples):",
        min_value=3,
        max_value=50,
        value=15,
        step=1,
        help="Numero minimo de vizinhos necessarios para consolidar um nucleo de agrupamento (core point)."
    )

    st.caption(f"Epsilon analitico sugerido pelo cotovelo (k={dados_processados['k_utilizado']}): **{eps_sugerido_calculado:.4f}**")

    st.markdown("---")
    st.markdown("### Projecao Bidimensional")
    modo_projecao = st.radio(
        "Modo de Mapeamento Espacial:",
        options=["PCA (Componentes Principais)", "Atributos Volumetricos de Rede"],
        index=0
    )

    st.markdown("---")
    st.markdown("### Simulacao Continua (Streaming)")
    modo_streaming = st.checkbox(
        "Ativar Modo de Monitoramento Continuo",
        value=False,
        help="Habilita a execucao em loop continuo de fluxos com atualizacao automatica dos graficos em tempo real."
    )

    if modo_streaming:
        intervalo_streaming = st.slider(
            "Intervalo por Ciclo (segundos):",
            min_value=0.5,
            max_value=3.0,
            value=1.0,
            step=0.5
        )
        total_ciclos_streaming = st.slider(
            "Quantidade de Ciclos no Loop:",
            min_value=5,
            max_value=30,
            value=10,
            step=5
        )
        tamanho_lote_streaming = st.select_slider(
            "Conexoes por Lote:",
            options=[1000, 2000, 3000, 5000],
            value=2000
        )
        iniciar_loop = st.button("Iniciar Monitoramento em Loop")

    st.markdown("---")
    st.caption("FIB - Inteligencia Artificial II\nAutores: Samuel, Bryan, Lucas, Renan.")


# ==================================================================================================
# CABECALHO INSTITUCIONAL
# ==================================================================================================

cenario_label = {
    "misto": "TRAFEGO MISTO (NORMAL + DDOS + PORTSCAN)",
    "ddos": "DDOS (FRIDAY AFTERNOON)",
    "portscan": "PORTSCAN (FRIDAY MORNING)"
}[cenario_selecionado]

st.markdown('<div class="header-title">CyberCluster: Triagem Nao Supervisionada de Conexoes de Rede</div>', unsafe_allow_html=True)
st.markdown(
    f'<div class="header-subtitle">'
    f'Avaliacao estrutural baseada em densidade (DBSCAN) sobre o dataset CICIDS2017. '
    f'Cenario ativo: <b>{cenario_label}</b> | '
    f'Dimensionalidade: <b>{dados_processados["X_scaled"].shape[1]} atributos</b>.'
    f'</div>',
    unsafe_allow_html=True
)


# ==================================================================================================
# EXECUCAO CONDICIONAL: MODO DE SIMULACAO CONTINUA (LOOP STREAMING)
# ==================================================================================================

if modo_streaming and iniciar_loop:
    st.markdown("#### Monitoramento em Tempo Real (Ciclo de Streaming Ativo)")
    st.caption("Executando ingestao e agrupamento em lotes sequenciais com taxa de amostragem periodica.")

    progresso_bar = st.progress(0)
    status_texto = st.empty()
    placeholder_metricas = st.empty()
    placeholder_graficos = st.empty()
    placeholder_tabela = st.empty()

    historico_taxa_ruido = []
    historico_ari = []
    historico_clusters = []
    eixos_ciclos = []

    for ciclo in range(total_ciclos_streaming):
        seed_atual = 200 + ciclo * 11
        X_lote_df, y_lote, X_lote_scaled = gerar_lote_streaming(
            cenario=cenario_selecionado,
            n_amostras=tamanho_lote_streaming,
            seed=seed_atual
        )

        # Ajuste DBSCAN no lote dinâmico
        dbscan_lote = DBSCAN(eps=eps_input, min_samples=min_samples_input, n_jobs=-1)
        labels_lote = dbscan_lote.fit_predict(X_lote_scaled)

        # Metricas instantaneas
        n_clusters_lote = len(np.unique(labels_lote[labels_lote != -1]))
        n_ruido_lote = int(np.sum(labels_lote == -1))
        pct_ruido_lote = float((n_ruido_lote / len(labels_lote)) * 100.0)
        ari_lote = float(adjusted_rand_score(y_lote, labels_lote))

        historico_taxa_ruido.append(pct_ruido_lote)
        historico_ari.append(ari_lote)
        historico_clusters.append(n_clusters_lote)
        eixos_ciclos.append(ciclo + 1)

        # Reducao PCA 2D para o lote
        pca_lote = PCA(n_components=2, random_state=42)
        coords_pca = pca_lote.fit_transform(X_lote_scaled)
        var_pca = pca_lote.explained_variance_ratio_

        # 1. Atualizacao dos KPIs
        with placeholder_metricas.container():
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Ciclo Ativo", f"{ciclo + 1}/{total_ciclos_streaming}")
            c2.metric("Clusters no Lote", f"{n_clusters_lote}")
            c3.metric("Taxa de Ruido", f"{pct_ruido_lote:.2f}%", f"{n_ruido_lote} fluxos")
            c4.metric("ARI no Lote", f"{ari_lote:.4f}")

        # 2. Atualizacao dos Graficos (Dispersao 2D + Curva Temporal)
        with placeholder_graficos.container():
            col_g1, col_g2 = st.columns(2)

            with col_g1:
                df_plot_lote = pd.DataFrame({
                    "PC1": coords_pca[:, 0],
                    "PC2": coords_pca[:, 1],
                    "Cluster": [f"Cluster {c}" if c != -1 else "Ruido (-1)" for c in labels_lote],
                    "Classe": y_lote.values
                })

                fig_lote = go.Figure()
                # Pontos de agrupamentos normais
                for cl in sorted([c for c in np.unique(labels_lote) if c != -1]):
                    mask = (labels_lote == cl)
                    fig_lote.add_trace(go.Scattergl(
                        x=df_plot_lote.loc[mask, "PC1"],
                        y=df_plot_lote.loc[mask, "PC2"],
                        mode='markers',
                        name=f"Cluster {cl}",
                        marker=dict(size=5, opacity=0.7)
                    ))
                # Ruido com simbolo 'x'
                mask_r = (labels_lote == -1)
                if np.any(mask_r):
                    fig_lote.add_trace(go.Scattergl(
                        x=df_plot_lote.loc[mask_r, "PC1"],
                        y=df_plot_lote.loc[mask_r, "PC2"],
                        mode='markers',
                        name="Ruido (-1)",
                        marker=dict(size=7, color='#DC2626', symbol='x', opacity=0.85)
                    ))

                fig_lote.update_layout(
                    title=f"Projecao PCA - Lote {ciclo + 1} (PC1: {var_pca[0]:.1%}, PC2: {var_pca[1]:.1%})",
                    xaxis_title="PC1",
                    yaxis_title="PC2",
                    template="plotly_white",
                    height=380,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig_lote, use_container_width=True)

            with col_g2:
                fig_tempo = go.Figure()
                fig_tempo.add_trace(go.Scatter(
                    x=eixos_ciclos,
                    y=historico_taxa_ruido,
                    mode='lines+markers',
                    name="Taxa de Ruido (%)",
                    line=dict(color='#DC2626', width=2)
                ))
                fig_tempo.add_trace(go.Scatter(
                    x=eixos_ciclos,
                    y=[a * 100 for a in historico_ari],
                    mode='lines+markers',
                    name="ARI (%)",
                    line=dict(color='#2563EB', width=2, dash='dot')
                ))
                fig_tempo.update_layout(
                    title="Evolucao Temporal das Metricas por Lote de Tráfego",
                    xaxis_title="Ciclo de Amostragem",
                    yaxis_title="Percentual (%)",
                    template="plotly_white",
                    height=380,
                    margin=dict(l=20, r=20, t=40, b=20),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                )
                st.plotly_chart(fig_tempo, use_container_width=True)

        # 3. Atualizacao da Matriz de Contingencia do Lote Corrente
        with placeholder_tabela.container():
            df_conting_lote = pd.DataFrame({
                "Cluster DBSCAN": [f"Cluster {c}" if c != -1 else "Ruido (-1)" for c in labels_lote],
                "Classe Real": y_lote.values
            })
            tab_cruzada_lote = pd.crosstab(
                df_conting_lote["Cluster DBSCAN"],
                df_conting_lote["Classe Real"],
                margins=True,
                margins_name="Total"
            )
            st.markdown(f"**Matriz de Contingencia - Lote {ciclo + 1} ({len(labels_lote):,} conexoes):**")
            st.dataframe(tab_cruzada_lote, use_container_width=True)

        progresso = (ciclo + 1) / total_ciclos_streaming
        progresso_bar.progress(progresso)
        status_texto.text(f"Status: Processando ciclo {ciclo + 1} de {total_ciclos_streaming}...")

        time.sleep(intervalo_streaming)

    status_texto.text(f"Concluido: Simulacao continua finalizada com sucesso. Total de {total_ciclos_streaming} ciclos processados.")
    st.markdown("---")


# ==================================================================================================
# EXECUCAO ESTÁTICA PADRÃO (DASHBOARD ANALÍTICO EM 5 ABAS)
# ==================================================================================================

X_df = dados_processados["X_sample"]
y_true = dados_processados["y_sample"]
X_scaled = dados_processados["X_scaled"]

# Executa o DBSCAN com os valores selecionados
labels_dbscan = computar_dbscan(X_scaled, eps=eps_input, min_samples=min_samples_input)

# Metricas do DBSCAN
mascara_validos = (labels_dbscan != -1)
labels_densos = labels_dbscan[mascara_validos]
n_clusters = len(np.unique(labels_densos))
n_ruido = int(np.sum(labels_dbscan == -1))
pct_ruido = float((n_ruido / len(labels_dbscan)) * 100.0)

ari_dbscan = float(adjusted_rand_score(y_true, labels_dbscan))

silhueta_core = None
davies_bouldin_core = None
if n_clusters >= 2 and len(labels_densos) > n_clusters:
    try:
        silhueta_core = float(silhouette_score(X_scaled[mascara_validos], labels_densos))
        davies_bouldin_core = float(davies_bouldin_score(X_scaled[mascara_validos], labels_densos))
    except Exception:
        pass

# PAINEL DE KPIS TECNICOS NO TOPO
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

with kpi1:
    st.metric(
        label="Clusters Densos",
        value=f"{n_clusters}",
        help="Quantidade de grupos densos identificados (excluindo pontos de ruido)."
    )

with kpi2:
    st.metric(
        label="Conexoes em Ruido",
        value=f"{n_ruido:,}",
        delta=f"{pct_ruido:.2f}% do trafego",
        delta_color="inverse",
        help="Volume e percentual de conexoes classificadas com label -1 (anomalias e pontos isolados)."
    )

with kpi3:
    st.metric(
        label="Silhueta (Nucleos)",
        value=f"{silhueta_core:.4f}" if silhueta_core is not None else "N/A",
        help="Coeficiente de Silhueta restrito aos clusters densos, sem distorcao do ruido."
    )

with kpi4:
    st.metric(
        label="Davies-Bouldin (Nucleos)",
        value=f"{davies_bouldin_core:.4f}" if davies_bouldin_core is not None else "N/A",
        help="Mede a similaridade entre clusters (valores menores indicam melhor separabilidade)."
    )

with kpi5:
    st.metric(
        label="Adjusted Rand Index",
        value=f"{ari_dbscan:.4f}",
        help="Concordancia ajustada ao acaso entre os agrupamentos descobertos e os rotulos reais do dataset."
    )

st.markdown("---")


# ==================================================================================================
# ABAS TEMATICAS
# ==================================================================================================

aba_projecao, aba_kdistance, aba_contingencia, aba_baseline, aba_exportacao = st.tabs([
    "Projecao Espacial 2D",
    "Curva de k-Distancias (Epsilon)",
    "Matriz de Contingencia",
    "Comparativo Baseline (K-Means)",
    "Relatorios e Exportacao JSON"
])


# --------------------------------------------------------------------------------------------------
# ABA 1: PROJECAO ESPACIAL 2D
# --------------------------------------------------------------------------------------------------
with aba_projecao:
    st.markdown("#### Dispersao Bidimensional das Conexoes")

    df_viz = pd.DataFrame()
    if modo_projecao == "PCA (Componentes Principais)":
        pca_coords, var_exp = computar_pca_2d(X_scaled)
        df_viz['Eixo_X'] = pca_coords[:, 0]
        df_viz['Eixo_Y'] = pca_coords[:, 1]
        rotulo_x = f"PC1 ({var_exp[0]:.1%} da variancia explicada)"
        rotulo_y = f"PC2 ({var_exp[1]:.1%} da variancia explicada)"
    else:
        cols_disp = [c for c in ['Flow Bytes/s', 'Total Fwd Packets', 'Flow Duration', 'Packet Length Mean'] if c in X_df.columns]
        c_x = cols_disp[0] if len(cols_disp) > 0 else X_df.columns[0]
        c_y = cols_disp[1] if len(cols_disp) > 1 else X_df.columns[1]
        df_viz['Eixo_X'] = np.log1p(np.maximum(0, X_df[c_x].values))
        df_viz['Eixo_Y'] = np.log1p(np.maximum(0, X_df[c_y].values))
        rotulo_x = f"log(1 + {c_x})"
        rotulo_y = f"log(1 + {c_y})"

    df_viz['Cluster_Rotulo'] = [f"Cluster {c}" if c != -1 else "Ruido / Anomalia (-1)" for c in labels_dbscan]
    df_viz['Classe_Real'] = y_true.values

    fig_disp = go.Figure()

    # Traco dos Clusters Densos
    clusters_ordenados = sorted([c for c in np.unique(labels_dbscan) if c != -1])
    paleta = px.colors.qualitative.Plotly

    for idx, c in enumerate(clusters_ordenados):
        mask = (labels_dbscan == c)
        cor = paleta[idx % len(paleta)]
        fig_disp.add_trace(go.Scattergl(
            x=df_viz.loc[mask, 'Eixo_X'],
            y=df_viz.loc[mask, 'Eixo_Y'],
            mode='markers',
            name=f"Cluster {c}",
            marker=dict(size=5, color=cor, opacity=0.7),
            customdata=df_viz.loc[mask, ['Cluster_Rotulo', 'Classe_Real']],
            hovertemplate="<b>%{customdata[0]}</b><br>Classe Real: %{customdata[1]}<br>X: %{x:.2f}<br>Y: %{y:.2f}<extra></extra>"
        ))

    # Traco do Ruido (-1) com simbolo 'x' de alto contraste
    mask_ruido = (labels_dbscan == -1)
    if np.any(mask_ruido):
        fig_disp.add_trace(go.Scattergl(
            x=df_viz.loc[mask_ruido, 'Eixo_X'],
            y=df_viz.loc[mask_ruido, 'Eixo_Y'],
            mode='markers',
            name="Ruido (-1)",
            marker=dict(size=6, color='#DC2626', symbol='x', opacity=0.85),
            customdata=df_viz.loc[mask_ruido, ['Cluster_Rotulo', 'Classe_Real']],
            hovertemplate="<b>RUIDO / ANOMALIA</b><br>Classe Real: %{customdata[1]}<br>X: %{x:.2f}<br>Y: %{y:.2f}<extra></extra>"
        ))

    fig_disp.update_layout(
        title=f"Espaco de Conexoes (Epsilon={eps_input}, Min_Samples={min_samples_input})",
        xaxis_title=rotulo_x,
        yaxis_title=rotulo_y,
        template="plotly_white",
        height=560,
        margin=dict(l=30, r=30, t=50, b=30),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_disp, use_container_width=True)


# --------------------------------------------------------------------------------------------------
# ABA 2: CURVA DE K-DISTANCIAS (ESTIMATIVA DO JOELHO DE EPSILON)
# --------------------------------------------------------------------------------------------------
with aba_kdistance:
    st.markdown("#### Curva de k-Distancias Ordenadas (k = 2 * d)")
    st.markdown(
        f"Conforme a fundamentacao de Ester et al. (1996) e Schubert et al. (2017), o hiperparametro "
        f"min_samples deve ser dimensionado proporcionalmente a dimensionalidade do espaco "
        f"(heuristica adotada: $k = 2 \\times {X_scaled.shape[1]} = {dados_processados['k_utilizado']}$). "
        f"O ponto de maior deflexao da curva (joelho) delimita a fronteira entre densidade intra-cluster e dispersao."
    )

    dists = dados_processados["dists_ordenadas"]
    idx_j = dados_processados["idx_joelho"]
    eps_sug = dados_processados["eps_sugerido"]

    fig_kdist = go.Figure()
    fig_kdist.add_trace(go.Scatter(
        x=np.arange(len(dists)),
        y=dists,
        mode='lines',
        name=f"k-distancia (k={dados_processados['k_utilizado']})",
        line=dict(color='#1E3A8A', width=2)
    ))

    fig_kdist.add_hline(
        y=eps_input,
        line_dash="dot",
        line_color="#2563EB",
        annotation_text=f"Epsilon Selecionado no Slider: {eps_input:.2f}",
        annotation_position="bottom right"
    )

    fig_kdist.add_hline(
        y=eps_sug,
        line_dash="dash",
        line_color="#DC2626",
        annotation_text=f"Joelho Analitico Estimado: {eps_sug:.4f}",
        annotation_position="top left"
    )

    fig_kdist.add_trace(go.Scatter(
        x=[idx_j],
        y=[eps_sug],
        mode='markers',
        name="Ponto de Joelho",
        marker=dict(size=10, color='#DC2626', symbol='circle')
    ))

    fig_kdist.update_layout(
        title=f"Analise de Cotovelo da Distancia ao k-esimo Vizinho (k={dados_processados['k_utilizado']})",
        xaxis_title="Indice da Conexao Ordenada por Proximidade",
        yaxis_title=f"Distancia Euclidiana ao {dados_processados['k_utilizado']}-esimo Vizinho",
        template="plotly_white",
        height=500,
        margin=dict(l=30, r=30, t=50, b=30),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_kdist, use_container_width=True)


# --------------------------------------------------------------------------------------------------
# ABA 3: MATRIZ DE CONTINGENCIA
# --------------------------------------------------------------------------------------------------
with aba_contingencia:
    st.markdown("#### Matriz de Contingencia (Clusters vs Ground Truth)")
    st.markdown(
        "Tabela cruzada demonstrando a distribuicao das classes reais de conexoes "
        "dentro de cada agrupamento inferido autonomamente pelo algoritmo DBSCAN."
    )

    df_contingencia = pd.DataFrame({
        'Cluster DBSCAN': [f"Cluster {c}" if c != -1 else "Ruido (-1)" for c in labels_dbscan],
        'Classe Real': y_true.values
    })

    tabela_cruzada = pd.crosstab(
        df_contingencia['Cluster DBSCAN'],
        df_contingencia['Classe Real'],
        margins=True,
        margins_name="Total Conexoes"
    )

    st.dataframe(
        tabela_cruzada.style.highlight_max(axis=0, color="#E2E8F0").format("{:,}"),
        use_container_width=True
    )

    if n_ruido > 0:
        st.markdown("##### Decomposicao das Conexoes Isoladas como Ruido (-1)")
        conexoes_ruido = df_contingencia[df_contingencia['Cluster DBSCAN'] == "Ruido (-1)"]['Classe Real'].value_counts()
        pct_conexoes_ruido = (conexoes_ruido / conexoes_ruido.sum()) * 100.0
        df_decomp_ruido = pd.DataFrame({
            "Volume Absoluto": conexoes_ruido,
            "Percentual no Ruido": pct_conexoes_ruido.map("{:.2f}%".format)
        })
        st.table(df_decomp_ruido)


# --------------------------------------------------------------------------------------------------
# ABA 4: COMPARATIVO BASELINE (K-MEANS)
# --------------------------------------------------------------------------------------------------
with aba_baseline:
    st.markdown("#### Comparacao Sistemica: K-Means (Baseline) vs DBSCAN (Principal)")

    kmeans = KMeans(n_clusters=3, init='k-means++', n_init=10, random_state=42)
    labels_km = kmeans.fit_predict(X_scaled)
    sil_km = float(silhouette_score(X_scaled, labels_km))
    ari_km = float(adjusted_rand_score(y_true, labels_km))
    db_km = float(davies_bouldin_score(X_scaled, labels_km))

    col_km, col_db = st.columns(2)

    with col_km:
        st.markdown("##### Baseline: K-Means (k=3)")
        st.metric("Silhouette Score", f"{sil_km:.4f}")
        st.metric("Adjusted Rand Index (ARI)", f"{ari_km:.4f}")
        st.metric("Davies-Bouldin Index", f"{db_km:.4f}")
        st.metric("Taxa de Ruido", "0.00% (Sem suporte a anomalias)")
        st.markdown("""
        **Comportamento Observado:**
        - Particao estritamente esferica baseada em minimizacao da variancia intra-cluster.
        - Conexoes anomalas sao forcadas a ingressar nos centroides principais.
        """)

    with col_db:
        st.markdown("##### Modelo Principal: DBSCAN")
        st.metric("Silhouette Score (Nucleos)", f"{silhueta_core:.4f}" if silhueta_core is not None else "N/A")
        st.metric("Adjusted Rand Index (ARI)", f"{ari_dbscan:.4f}")
        st.metric("Davies-Bouldin Index", f"{davies_bouldin_core:.4f}" if davies_bouldin_core is not None else "N/A")
        st.metric("Taxa de Ruido", f"{pct_ruido:.2f}% ({n_ruido:,} conexoes)")
        st.markdown("""
        **Comportamento Observado:**
        - Descoberta organica de fronteiras densas de geometria arbitraria.
        - Isolamento matematico nativo de varreduras e pacotes atipicos no rotulo -1.
        """)


# --------------------------------------------------------------------------------------------------
# ABA 5: RELATORIOS E EXPORTACAO JSON
# --------------------------------------------------------------------------------------------------
with aba_exportacao:
    st.markdown("#### Exportacao Estruturada de Metricas e Contingencia")
    st.markdown(
        "Os dados gerados nesta sessao interativa podem ser exportados em formato JSON "
        "para consumo por pipelines de integracao de seguranca ou relatorios tecnicos."
    )

    dados_relatorio = {
        "projeto": "CyberCluster",
        "cenario": cenario_selecionado,
        "instancias": len(X_scaled),
        "dimensionalidade": X_scaled.shape[1],
        "k_distance": {
            "k_utilizado": dados_processados["k_utilizado"],
            "indice_joelho": dados_processados["idx_joelho"],
            "epsilon_estimado": dados_processados["eps_sugerido"]
        },
        "dbscan": {
            "eps": eps_input,
            "min_samples": min_samples_input,
            "clusters_encontrados": n_clusters,
            "conexoes_ruido": n_ruido,
            "percentual_ruido": pct_ruido,
            "silhouette_core": silhueta_core,
            "davies_bouldin_core": davies_bouldin_core,
            "ari": ari_dbscan
        }
    }

    contingencia_export = {
        str(idx): {str(col): int(val) for col, val in row.items()}
        for idx, row in tabela_cruzada.iterrows()
    }

    col_exp1, col_exp2 = st.columns(2)

    with col_exp1:
        st.markdown("##### Resumo de Metricas (JSON)")
        st.json(dados_relatorio)
        st.download_button(
            label="Baixar metrics_summary.json",
            data=json.dumps(dados_relatorio, indent=4),
            file_name="metrics_summary.json",
            mime="application/json"
        )

    with col_exp2:
        st.markdown("##### Matriz de Contingencia (JSON)")
        st.json(contingencia_export)
        st.download_button(
            label="Baixar contingency_matrix.json",
            data=json.dumps(contingencia_export, indent=4),
            file_name="contingency_matrix.json",
            mime="application/json"
        )
