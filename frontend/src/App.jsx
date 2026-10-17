import { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [resultado, setResultado] = useState(null);
  const [carregando, setCarregando] = useState(false);
  const [erro, setErro] = useState('');

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/predict';

  const analisarUrl = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setCarregando(true);
    setErro('');
    setResultado(null);

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.erro || 'Erro ao processar a requisição.');
      }
      setResultado(data);
    } catch (err) {
      setErro('Não foi possível conectar à API Flask. Verifique se o backend está ativo na porta 5000.');
    } finally {
      setCarregando(false);
    }
  };

  const preencherExemplo = (urlExemplo) => {
    setUrl(urlExemplo);
    setResultado(null);
    setErro('');
  };

  const isPerigo = resultado?.codigo_classe === 1;

  return (
    <div className="app-wrapper">
      <div className="container">
        <header className="header">
          <div className="brand-badge"> SISTEMA DE DETECÇÃO DE AMEAÇAS</div>
          <h1> 🛡️PhishGuard ML</h1>
          <p>
            Análise léxica e estrutural de URLs em tempo real utilizando{' '}
            <strong>Random Forest

            </strong>
          </p>
        </header>

        <section className="search-section">
          <form onSubmit={analisarUrl} className="search-box">
            <input
              type="text"
              placeholder="Insira a URL completa para inspeção (ex: http://login-banco-atualizacao.xyz/conta)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            <button type="submit" disabled={carregando}>
              {carregando ? 'Processando...' : 'Analisar URL'}
            </button>
          </form>

          <div className="exemplos">
            <span className="exemplos-label">Exemplos para teste:</span>
            <button
              type="button"
              className="btn-exemplo"
              onClick={() => preencherExemplo('https://www.unifei.edu.br/cursos/graduacao')}
            >
              ✅ URL Segura
            </button>
            <button
              type="button"
              className="btn-exemplo"
              onClick={() => preencherExemplo('http://login-banco-atualizacao.xyz/conta')}
            >
              🚨 URL Phishing
            </button>
          </div>
        </section>

        {erro && <div className="alerta-erro">{erro}</div>}

        {resultado && (
          <div className={`card-resultado ${isPerigo ? 'perigo' : 'seguro'}`}>
            <div className="cabecalho-resultado">
              <div className="status-titulo">
                <span className={`status-dot ${isPerigo ? 'dot-perigo' : 'dot-seguro'}`} />
                <h2>
                  {isPerigo ? 'Ameaça Detectada: URL Maliciosa / Phishing' : 'URL Legítima e Segura'}
                </h2>
              </div>
              <span className={`badge-risco ${isPerigo ? 'badge-perigo' : 'badge-seguro'}`}>
                Risco {resultado.nivel_risco}
              </span>
            </div>

            <div className="url-box">
              <span className="url-label">URL Inspecionada</span>
              <code className="url-analisada">{resultado.url}</code>
            </div>

            <div className="painel-probabilidades">
              <div className="metrica-card">
                <span className="metrica-titulo">Probabilidade de Phishing</span>
                <strong className={`metrica-valor ${isPerigo ? 'texto-perigo' : ''}`}>
                  {resultado.probabilidade_phishing}%
                </strong>
              </div>
              <div className="metrica-card">
                <span className="metrica-titulo">Índice de Segurança</span>
                <strong className={`metrica-valor ${!isPerigo ? 'texto-seguro' : ''}`}>
                  {resultado.probabilidade_segura}%
                </strong>
              </div>
            </div>

            <div className="barra-progresso-container">
              <div
                className={`barra-progresso-fill ${isPerigo ? 'fill-perigo' : 'fill-seguro'}`}
                style={{ width: `${Math.max(resultado.probabilidade_phishing, 3)}%` }}
              />
            </div>

            {resultado.motivos_alerta && (
              <div className="painel-motivos">
                <h3>Laudo Técnico da Análise</h3>
                <ul>
                  {resultado.motivos_alerta.map((motivo, idx) => (
                    <li key={idx}>{motivo}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="secao-features">
              <h3>Vetor de Atributos Extraídos (Random Forest)</h3>
              <div className="grid-features">
                <div className="feature-item">
                  <span>Comprimento Total</span>
                  <strong>{resultado.features_extraidas.tamanho_url} caract.</strong>
                </div>
                <div className="feature-item">
                  <span>Comprimento do Domínio</span>
                  <strong>{resultado.features_extraidas.tamanho_dominio} caract.</strong>
                </div>
                <div className="feature-item">
                  <span>Endereço IP Direto</span>
                  <strong>{resultado.features_extraidas.usa_ip ? 'Sim (1)' : 'Não (0)'}</strong>
                </div>
                <div className="feature-item">
                  <span>TLD Suspeito / Encurtador</span>
                  <strong>{resultado.features_extraidas.tld_suspeito ? 'Sim (1)' : 'Não (0)'}</strong>
                </div>
                <div className="feature-item">
                  <span>TLD Institucional</span>
                  <strong>{resultado.features_extraidas.tld_confiavel ? 'Sim (1)' : 'Não (0)'}</strong>
                </div>
                <div className="feature-item">
                  <span>Hífens no Domínio</span>
                  <strong>{resultado.features_extraidas.qtd_hifens_dominio}</strong>
                </div>
                <div className="feature-item">
                  <span>Qtd. de Subdomínios</span>
                  <strong>{resultado.features_extraidas.qtd_subdominios}</strong>
                </div>
                <div className="feature-item">
                  <span>Termos Sensíveis</span>
                  <strong>{resultado.features_extraidas.qtd_palavras_suspeitas}</strong>
                </div>
                <div className="feature-item">
                  <span>Extensão Sensível (.php/.exe)</span>
                  <strong>{resultado.features_extraidas.tem_extensao_sensivel ? 'Sim (1)' : 'Não (0)'}</strong>
                </div>
                <div className="feature-item">
                  <span>Entropia de Shannon (URL)</span>
                  <strong>{resultado.features_extraidas.entropia_url} bits</strong>
                </div>
                <div className="feature-item">
                  <span>Pontos (.) / Barras (/)</span>
                  <strong>
                    {resultado.features_extraidas.qtd_pontos} / {resultado.features_extraidas.qtd_barras}
                  </strong>
                </div>
                <div className="feature-item">
                  <span>Proporção de Dígitos</span>
                  <strong>
                    {resultado.features_extraidas.qtd_digitos} (
                    {(resultado.features_extraidas.proporcao_digitos * 100).toFixed(1)}%)
                  </strong>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;