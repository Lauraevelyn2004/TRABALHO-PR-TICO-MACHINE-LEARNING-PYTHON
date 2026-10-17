from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from extrator import extrair_features_url, COLUNAS_FEATURES

app = Flask(__name__)
CORS(app)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# Carregar o modelo Random Forest treinado
modelo = joblib.load("modelo_pkl" if False else "modelo_rf.pkl")

def gerar_explicacao_risco(features: dict, prob_phishing: float) -> list:
    motivos = []
    if features['usa_ip'] == 1:
        motivos.append("Usa endereço IP numérico direto em vez de um domínio registrado.")
    if features['tld_suspeito'] == 1:
        motivos.append("Terminação de domínio (TLD) ou encurtador frequentemente associado a campanhas de phishing.")
    if features['qtd_hifens_dominio'] >= 2:
        motivos.append(f"Domínio contém múltiplos hífens ({features['qtd_hifens_dominio']}), padrão comum em domínios falsos.")
    if features['qtd_palavras_suspeitas'] >= 1:
        motivos.append(f"Detectados {features['qtd_palavras_suspeitas']} termo(s) sensível(is) de engenharia social (ex: login, bank, conta, verify).")
    if features['tem_extensao_sensivel'] == 1:
        motivos.append("Caminho aponta para script dinâmico ou arquivo executável (.php, .exe, .scr, etc.).")
    if features['qtd_subdominios'] >= 2:
        motivos.append(f"Excesso de subdomínios ({features['qtd_subdominios']}), técnica usada para mascarar o domínio real.")
    if features['entropia_url'] >= 4.3:
        motivos.append(f"Alta entropia de caracteres ({features['entropia_url']}), indicando tokens aleatórios ou ofuscação.")
    if features['tld_confiavel'] == 1 and prob_phishing < 50:
        motivos.append("Domínio institucional de alta confiança (.edu.br, .gov.br, .edu, .gov).")
    if not motivos:
        if prob_phishing >= 50:
            motivos.append("Combinação estrutural de comprimento, diretórios e dígitos típica de URLs maliciosas.")
        else:
            motivos.append("Estrutura léxica limpa, baixa entropia e ausência de indicadores de phishing.")
    return motivos

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "servico": "API PhishGuard ML - Detecção Avançada de URLs Maliciosas (Random Forest - 22 Features)"
    })

@app.route("/predict", methods=["POST"])
def predict():
    try:
        dados = request.get_json(silent=True)
        if not dados or "url" not in dados:
            return jsonify({"erro": "Por favor, envie o campo 'url' no corpo do JSON."}), 400

        url_recebida = str(dados["url"]).strip()
        if not url_recebida:
            return jsonify({"erro": "A URL não pode estar vazia."}), 400

        # 1. Extrair os 22 atributos normalizados da URL
        features_dict = extrair_features_url(url_recebida)
        
        # Converter em vetor ordenado sem usar pandas
        vetor_features = [features_dict[col] for col in COLUNAS_FEATURES]

        # 2. Inferência com o modelo Random Forest
        classe_predita = int(modelo.predict([vetor_features])[0])
        probabilidades = modelo.predict_proba([vetor_features])[0]

        risco_phishing = round(float(probabilidades[1]) * 100, 2)
        confianca_segura = round(float(probabilidades[0]) * 100, 2)

        # 3. Classificar nível de severidade
        if risco_phishing >= 80:
            nivel_risco = "Crítico"
        elif risco_phishing >= 50:
            nivel_risco = "Alto"
        elif risco_phishing >= 25:
            nivel_risco = "Moderado"
        else:
            nivel_risco = "Baixo (Seguro)"

        motivos = gerar_explicacao_risco(features_dict, risco_phishing)

        return jsonify({
            "url": url_recebida,
            "classificacao": "Maliciosa / Phishing" if classe_predita == 1 else "URL Segura",
            "codigo_classe": classe_predita,
            "nivel_risco": nivel_risco,
            "probabilidade_phishing": risco_phishing,
            "probabilidade_segura": confianca_segura,
            "motivos_alerta": motivos,
            "features_extraidas": features_dict
        })
    except Exception as e:
        return jsonify({"erro": f"Erro interno na API: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)