import re
import math
from collections import Counter
from urllib.parse import urlparse

# Lista expandida de termos de engenharia social (Inglês + Português)
PALAVRAS_SUSPEITAS = [
    'login', 'secure', 'bank', 'update', 'verify', 'account',
    'confirm', 'password', 'signin', 'free', 'bonus', 'pix', 'seguro',
    'banco', 'atualizacao', 'atualizar', 'conta', 'verifica', 'token',
    'icloud', 'paypal', 'netflix', 'appleid', 'support', 'auth',
    'credential', 'wallet', 'crypto', 'urgent', 'suspend', 'bloqueado',
    'acesso', 'senha', 'cadastro', 'premio', 'resgate', 'webscr', 'cmd',
    'wp-admin', 'wp-content', 'includes', 'cgi-bin', 'onedrive', 'office365'
]

# TLDs frequentemente abusados em campanhas de phishing
TLDS_SUSPEITOS = (
    '.xyz', '.top', '.club', '.info', '.site', '.online', '.vip',
    '.icu', '.buzz', '.work', '.click', '.loan', '.tk', '.ml',
    '.ga', '.cf', '.gq', '.pw', '.cc', '.su', '.rest', '.fit'
)

# TLDs institucionais de alta confiança ( exigem validação rígida de registro )
TLDS_CONFIAVEIS = (
    '.edu.br', '.gov.br', '.mil.br', '.jus.br', '.leg.br',
    '.edu', '.gov', '.mil', '.ac.uk'
)

# Serviços encurtadores de URL usados para ocultar links maliciosos
ENCURTADORES = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'cli.gs',
    'tiny.cc', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'shorturl.at', 'ow.ly'
}

COLUNAS_FEATURES = [
    'tamanho_url', 'tamanho_dominio', 'tamanho_caminho',
    'qtd_pontos', 'qtd_hifens', 'qtd_hifens_dominio',
    'qtd_barras', 'qtd_interrogacoes', 'qtd_iguais',
    'qtd_arrobas', 'qtd_percentuais', 'qtd_digitos',
    'qtd_digitos_dominio', 'proporcao_digitos', 'usa_ip',
    'qtd_subdominios', 'tld_suspeito', 'tld_confiavel',
    'tem_extensao_sensivel', 'qtd_palavras_suspeitas',
    'entropia_url', 'entropia_dominio'
]

def calcular_entropia(texto: str) -> float:
    """Calcula a Entropia de Shannon para medir a aleatoriedade da string."""
    if not texto:
        return 0.0
    contagem = Counter(texto)
    tamanho = len(texto)
    return round(
        -sum((freq / tamanho) * math.log2(freq / tamanho) for freq in contagem.values()),
        4
    )

def extrair_features_url(url: str) -> dict:
    """Extrai 22 atributos léxicos e estruturais normalizados de uma URL."""
    url_raw = str(url).strip().lower()
    # Remove aspas acidentais presentes em algumas linhas de CSVs públicos
    url_raw = url_raw.strip("'\"")

    # 1. Isolar e remover protocolo (http:// ou https://) para evitar viés de coleta
    url_sem_proto = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', url_raw)

    # 2. Separar domínio, caminho e query com proteção contra colchetes inválidos
    try:
        parsed = urlparse('http://' + url_sem_proto)
        host = (parsed.netloc or '').split(':')[0]
        caminho = parsed.path or ''
        query = parsed.query or ''
    except ValueError:
        partes = url_sem_proto.split('/', 1)
        host = partes[0].split(':')[0]
        resto = '/' + partes[1] if len(partes) > 1 else ''
        if '?' in resto:
            caminho, query = resto.split('?', 1)
        else:
            caminho, query = resto, ''

    # 3. Normalizar prefixo 'www.' (ex: www., www1., www2.) para evitar viés
    host_limpo = re.sub(r'^www\d*\.', '', host)
    caminho_limpo = caminho if caminho != '/' else ''
    url_norm = host_limpo + caminho_limpo + (('?' + query) if query else '')

    # 4. Medidas de comprimento
    tamanho_url = len(url_norm)
    tamanho_dominio = len(host_limpo)
    tamanho_caminho = len(caminho_limpo) + (len(query) + 1 if query else 0)

    # 5. Contagem de caracteres estruturais
    qtd_pontos = url_norm.count('.')
    qtd_hifens = url_norm.count('-')
    qtd_hifens_dominio = host_limpo.count('-')
    qtd_barras = url_norm.count('/')
    qtd_interrogacoes = url_norm.count('?')
    qtd_iguais = url_norm.count('=')
    qtd_arrobas = url_norm.count('@')
    qtd_percentuais = url_norm.count('%')

    # 6. Contagem e proporção de dígitos
    qtd_digitos = sum(c.isdigit() for c in url_norm)
    qtd_digitos_dominio = sum(c.isdigit() for c in host_limpo)
    proporcao_digitos = round(qtd_digitos / max(tamanho_url, 1), 4)

    # 7. Verifica se o host é um endereço IPv4 numérico
    padrao_ip = r'^(\d{1,3}\.){3}\d{1,3}$'
    usa_ip = 1 if re.match(padrao_ip, host_limpo) else 0

    # 8. Cálculo de subdomínios (descontando TLDs compostos como .com.br, .edu.br, .co.uk)
    partes_dom = [p for p in host_limpo.split('.') if p]
    tem_tld_composto = 1 if re.search(
        r'\.(com|edu|gov|org|net|co|ac|jus|mil|leg|ind|art|esp)\.[a-z]{2}$',
        host_limpo
    ) else 0
    qtd_subdominios = max(0, len(partes_dom) - (3 if tem_tld_composto else 2)) if not usa_ip else 0

    # 9. Reputação do TLD e encurtadores
    tld_suspeito = 1 if (host_limpo.endswith(TLDS_SUSPEITOS) or host_limpo in ENCURTADORES) else 0
    tld_confiavel = 1 if host_limpo.endswith(TLDS_CONFIAVEIS) else 0

    # 10. Extensões sensíveis (.php, .exe, .scr, .apk, .zip, .cmd, .bat)
    tem_extensao_sensivel = 1 if re.search(
        r'\.(php|exe|scr|zip|rar|apk|bat|sh|cmd|dll|jsp|asp|cgi|ini)(\b|$|\?|/)',
        caminho_limpo.lower()
    ) else 0

    # 11. Quantidade de palavras-chave suspeitas
    qtd_palavras_suspeitas = sum(1 for p in PALAVRAS_SUSPEITAS if p in url_norm)

    # 12. Entropia de Shannon (URL completa e apenas domínio)
    entropia_url = calcular_entropia(url_norm)
    entropia_dominio = calcular_entropia(host_limpo)

    return {
        'tamanho_url': tamanho_url,
        'tamanho_dominio': tamanho_dominio,
        'tamanho_caminho': tamanho_caminho,
        'qtd_pontos': qtd_pontos,
        'qtd_hifens': qtd_hifens,
        'qtd_hifens_dominio': qtd_hifens_dominio,
        'qtd_barras': qtd_barras,
        'qtd_interrogacoes': qtd_interrogacoes,
        'qtd_iguais': qtd_iguais,
        'qtd_arrobas': qtd_arrobas,
        'qtd_percentuais': qtd_percentuais,
        'qtd_digitos': qtd_digitos,
        'qtd_digitos_dominio': qtd_digitos_dominio,
        'proporcao_digitos': proporcao_digitos,
        'usa_ip': usa_ip,
        'qtd_subdominios': qtd_subdominios,
        'tld_suspeito': tld_suspeito,
        'tld_confiavel': tld_confiavel,
        'tem_extensao_sensivel': tem_extensao_sensivel,
        'qtd_palavras_suspeitas': qtd_palavras_suspeitas,
        'entropia_url': entropia_url,
        'entropia_dominio': entropia_dominio
    }