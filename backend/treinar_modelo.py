import os
import random
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)
from extrator import extrair_features_url, COLUNAS_FEATURES

random.seed(42)

def gerar_exemplos_complementares():
    """
    Gera exemplos complementares de domínios raiz legítimos e URLs de phishing brasileiras
    para corrigir o viés do kaggle_urls.csv (onde 99,9% das URLs benignas possuem barra '/').
    """
    dominios_confiaveis = [
        "google.com", "google.com.br", "github.com", "stackoverflow.com", "wikipedia.org",
        "unifei.edu.br", "usp.br", "unicamp.br", "ufmg.br", "gov.br", "scielo.br",
        "python.org", "react.dev", "microsoft.com", "apple.com", "amazon.com.br",
        "youtube.com", "impa.br", "cnpq.br", "capes.gov.br", "itau.com.br",
        "bradesco.com.br", "bb.com.br", "nubank.com.br", "mercadolivre.com.br",
        "globo.com", "uol.com.br", "estadao.com.br", "folha.uol.com.br", "linkedin.com"
    ]
    caminhos_confiaveis = [
        "", "/", "/cursos/graduacao", "/pt-br", "/docs", "/about", "/help",
        "/noticias/2026", "/artigos/ciencia-de-dados", "/pesquisa/pos-graduacao",
        "/portal/servicos", "/ institucional", "/biblioteca/acervo"
    ]

    dominios_phishing_br = [
        "login-banco-atualizacao.xyz", "secure-login-update.xyz", "banco-verifica-conta.top",
        "192.168.45.12", "200.145.10.88", "45.33.32.156", "apple-id-confirm-account.info",
        "pix-bonus-free.club", "signin-account-security-alert.net", "update-password-bank-now.org",
        "itau-atualizar-token-seguro.xyz", "nubank-verifica-acesso.top", "govbr-resgate-valores-pix.icu",
        "bradesco-seguranca-token.site", "netflix-update-billing-account.info",
        "correios-taxa-entrega-atualizacao.xyz", "caixa-tem-bloqueio-conta.club"
    ]
    caminhos_phishing_br = [
        "/conta", "/login", "/verify", "/login/verify/bank-account-update.php",
        "/secure/signin/confirm-password.php", "/bank/pix-free-bonus/login",
        "/account/verify-now/index.html", "/update-security-token/login/confirm?session=9841249",
        "/auth/login.php?cmd=_login-run&dispatch=5885d80a13c0db1f"
    ]

    urls_extras = []
    # 2.500 URLs legítimas (incluindo domínios raiz e subcaminhos com/sem https e www)
    for i in range(2500):
        dom = random.choice(dominios_confiaveis)
        cam = random.choice(caminhos_confiaveis)
        proto = "https://" if random.random() > 0.15 else "http://"
        www = "www." if random.random() > 0.4 else ""
        sufixo = f"/{i}" if (cam and random.random() > 0.6) else ""
        urls_extras.append({"url": f"{proto}{www}{dom}{cam}{sufixo}", "classe": 0})

    # 2.500 URLs de phishing focadas em padrões modernos de engenharia social
    for i in range(2500):
        dom = random.choice(dominios_phishing_br)
        cam = random.choice(caminhos_phishing_br)
        proto = "http://" if random.random() > 0.3 else "https://"
        token = f"?id={random.randint(10000, 999999)}&login=true" if random.random() > 0.5 else ""
        urls_extras.append({"url": f"{proto}{dom}{cam}{token}", "classe": 1})

    return pd.DataFrame(urls_extras)

def carregar_e_preparar_dataset(caminho_kaggle="kaggle_urls.csv", n_por_classe=20000):
    if os.path.exists(caminho_kaggle):
        print(f"[INFO] Carregando base real '{caminho_kaggle}'...")
        df_raw = pd.read_csv(caminho_kaggle).dropna(subset=['url', 'type'])

        # Remover o bloco final ruidoso (índice > 586000) onde URLs legítimas sem protocolo
        # foram misturadas na classe phishing na compilação original do Kaggle
        df_limpo = df_raw.iloc[:586000].copy()

        # Separar URLs benignas (Classe 0) e maliciosas confirmadas (Classe 1)
        df_benign = df_limpo[df_limpo['type'] == 'benign'].sample(
            n=min(n_por_classe, (df_limpo['type'] == 'benign').sum()),
            random_state=42
        )
        df_benign['classe'] = 0

        # Para phishing/malware/defacement, priorizar registros com estrutura completa
        df_mal = df_limpo[df_limpo['type'].isin(['phishing', 'malware', 'defacement'])].sample(
            n=min(n_por_classe, df_limpo['type'].isin(['phishing', 'malware', 'defacement']).sum()),
            random_state=42
        )
        df_mal['classe'] = 1

        df_kaggle = pd.concat([df_benign[['url', 'classe']], df_mal[['url', 'classe']]], ignore_index=True)
        df_comp = gerar_exemplos_complementares()
        df_total = pd.concat([df_kaggle, df_comp], ignore_index=True)
        print(f"[OK] Base combinada carregada: {len(df_total)} URLs ({len(df_kaggle)} do Kaggle + {len(df_comp)} complementares).")
    else:
        print("[AVISO] 'kaggle_urls.csv' não encontrado. Usando base complementar expandida.")
        df_total = gerar_exemplos_complementares()

    # Embaralhar dataset
    df_total = df_total.sample(frac=1, random_state=42).reset_index(drop=True)

    # Extrair as 22 features de cada URL
    print("[INFO] Extraindo 22 atributos léxicos e de entropia das URLs...")
    lista_features = []
    for u, c in zip(df_total['url'], df_total['classe']):
        feat = extrair_features_url(u)
        feat['url_original'] = u
        feat['classe'] = int(c)
        lista_features.append(feat)

    df_final = pd.DataFrame(lista_features)
    df_final.to_csv("dataset_urls.csv", index=False)
    print(f"[OK] Dataset processado salvo em 'dataset_urls.csv' com {len(df_final)} tuplas.")
    return df_final

if __name__ == "__main__":
    # 1. Construir e pré-processar o conjunto de dados
    df = carregar_e_preparar_dataset("kaggle_urls.csv", n_por_classe=20000)

    X = df[COLUNAS_FEATURES]
    y = df['classe']

    # 2. Dividir em Treino (80%) e Teste (20%) com estratificação
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Exportar arquivo de teste SEM a coluna alvo (requisito do projeto)
    X_test.to_csv("teste_sem_classificador.csv", index=False)
    print("[OK] Arquivo 'teste_sem_classificador.csv' exportado sem a coluna alvo.")

    # 4. Configurar e treinar o Random Forest otimizado
    modelo = RandomForestClassifier(
        n_estimators=250,
        max_depth=22,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )

    # 5. Validação Cruzada Estratificada (5-Fold Cross-Validation)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores_cv = cross_val_score(modelo, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
    print("\n--- VALIDAÇÃO CRUZADA ESTRATIFICADA (5-Folds) ---")
    print(f"Acurácia Média CV: {scores_cv.mean():.4f} (+/- {scores_cv.std():.4f})")

    # Treinamento final no conjunto de treino
    modelo.fit(X_train, y_train)

    # 6. Avaliação no conjunto de teste lendo do arquivo sem classificador
    X_teste_sem_classe = pd.read_csv("teste_sem_classificador.csv")
    y_pred = modelo.predict(X_teste_sem_classe)
    y_prob = modelo.predict_proba(X_teste_sem_classe)[:, 1]

    print("\n--- MÉTRICAS NO CONJUNTO DE TESTE (20%) ---")
    print(f"Acurácia (Accuracy):  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precisão (Precision): {precision_score(y_test, y_pred):.4f}")
    print(f"Revocação (Recall):   {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score:             {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC Score:        {roc_auc_score(y_test, y_prob):.4f}")
    print("\nMatriz de Confusão:")
    print(confusion_matrix(y_test, y_pred))
    print("\nRelatório Detalhado:")
    print(classification_report(y_test, y_pred, target_names=['Segura (0)', 'Maliciosa/Phishing (1)']))

    # 7. Ranking de Importância dos Atributos
    importancias = pd.Series(modelo.feature_importances_, index=COLUNAS_FEATURES).sort_values(ascending=False)
    print("\nTop 10 Atributos Mais Importantes no Random Forest:")
    print(importancias.head(10))

    # 8. Salvar o modelo treinado
    joblib.dump(modelo, "modelo_rf.pkl", compress=3)
    print("\n[OK] Modelo exportado com sucesso para 'modelo_rf.pkl'!")